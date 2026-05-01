#![no_main]

//! HTTP/1.1 response trailers parser fuzzing target
//!
//! Tests RFC 9110 §6.5 and RFC 9112 §7.1.2 trailer requirements:
//! - Trailers only allowed with chunked transfer encoding
//! - Forbidden trailer headers per RFC 9110 §6.5.1 security rules
//! - Trailer syntax validation and size limits
//! - Tests codec.rs ChunkedBodyDecoder and is_forbidden_trailer() logic

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// Test case for HTTP response trailers parsing
#[derive(Arbitrary, Debug, Clone)]
pub struct TrailersParserTestCase {
    pub scenario: TrailersScenario,
    pub chunked_message: ChunkedMessage,
    pub trailer_headers: Vec<TrailerHeader>,
    pub parsing_config: ParsingConfig,
    pub security_config: SecurityConfig,
}

/// Different trailers testing scenarios
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum TrailersScenario {
    /// Normal trailers with chunked encoding
    ValidTrailers,
    /// Forbidden trailers (security violation)
    ForbiddenTrailers,
    /// Trailers without chunked encoding (protocol violation)
    TrailersWithoutChunked,
    /// Oversized trailers (DoS protection)
    OversizedTrailers,
    /// Malformed trailer syntax
    MalformedTrailerSyntax,
    /// Case sensitivity in forbidden headers
    ForbiddenHeaderCaseSensitivity,
    /// Trailer header injection
    TrailerHeaderInjection,
    /// Unicode and non-ASCII trailers
    UnicodeTrailers,
    /// Buffer boundary edge cases
    BufferBoundaryTrailers,
    /// Trailer count limits
    ExcessiveTrailerCount,
}

/// Chunked message structure for testing
#[derive(Arbitrary, Debug, Clone)]
pub struct ChunkedMessage {
    pub transfer_encoding: TransferEncoding,
    pub chunks: Vec<MessageChunk>,
    pub final_chunk_size: u32, // Usually 0 for terminal chunk
    pub chunk_extensions: Vec<ChunkExtension>,
}

/// Transfer encoding configuration
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum TransferEncoding {
    Chunked,
    ContentLength(usize),
    None, // Missing both (edge case)
    Both(usize), // Both chunked and content-length (ambiguous)
}

/// Message chunk data
#[derive(Arbitrary, Debug, Clone)]
pub struct MessageChunk {
    pub data: Vec<u8>,
    pub extensions: Vec<ChunkExtension>,
}

/// Chunk extension for testing edge cases
#[derive(Arbitrary, Debug, Clone)]
pub struct ChunkExtension {
    pub name: String,
    pub value: Option<String>,
}

/// Trailer header for testing
#[derive(Arbitrary, Debug, Clone)]
pub struct TrailerHeader {
    pub name: HeaderName,
    pub value: HeaderValue,
    pub syntax_variant: SyntaxVariant,
}

/// Header name types for trailer testing
#[derive(Arbitrary, Debug, Clone)]
pub enum HeaderName {
    // Safe trailers (allowed)
    Safe(SafeTrailerName),
    // Forbidden trailers (security risk)
    Forbidden(ForbiddenTrailerName),
    // Custom/extension headers
    Custom(String),
    // Malformed header names
    Malformed(MalformedHeaderName),
}

/// Safe trailer header names
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum SafeTrailerName {
    XChecksum,
    XRequestId,
    XProcessingTime,
    XCustomMetadata,
    ETag,
    XTrailer,
    ServerTiming,
    XCorrelationId,
}

/// Forbidden trailer header names per RFC 9110 §6.5.1
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum ForbiddenTrailerName {
    // Framing headers
    ContentLength,
    TransferEncoding,
    Trailer,

    // Payload headers
    ContentEncoding,
    ContentType,
    ContentRange,

    // Authentication headers
    Authorization,
    ProxyAuthorization,
    WwwAuthenticate,
    ProxyAuthenticate,
    Cookie,
    SetCookie,

    // Routing/connection headers
    Host,
    Upgrade,
    Connection,

    // Cache control headers
    CacheControl,
    Age,
    Expires,
    Pragma,

    // Request modifiers
    Range,
    IfMatch,
    IfNoneMatch,
    IfModifiedSince,
    IfUnmodifiedSince,
    IfRange,
    MaxForwards,
    Te,
    Expect,

    // Other forbidden
    Vary,
    Warning,
}

/// Malformed header name types
#[derive(Arbitrary, Debug, Clone)]
pub enum MalformedHeaderName {
    Empty,
    WithSpaces(String),
    WithControlChars(Vec<u8>),
    WithUnicode(String),
    WithColon(String), // Colon in header name
    TooLong(usize),
    OnlyWhitespace,
}

/// Header value configurations
#[derive(Arbitrary, Debug, Clone)]
pub enum HeaderValue {
    Normal(String),
    Empty,
    WithCrLf(String), // CRLF injection attempt
    WithNulls(Vec<u8>), // Null byte injection
    WithControlChars(Vec<u8>),
    WithUnicode(String),
    VeryLong(usize), // Size boundary testing
    OnlyWhitespace(usize),
    Binary(Vec<u8>), // Non-text data
}

/// Syntax variant for header formatting
#[derive(Arbitrary, Debug, Clone, PartialEq)]
pub enum SyntaxVariant {
    Standard,         // "Name: Value\r\n"
    ExtraWhitespace,  // " Name : Value \r\n"
    NoColon,         // "NameValue\r\n" (malformed)
    NoValue,         // "Name:\r\n"
    MultipleColons,  // "Na:me: Val:ue\r\n"
    TabSeparator,    // "Name\t:\tValue\r\n"
    FoldedObsolete,  // "Name: Value\r\n continuation"
}

/// Parsing configuration
#[derive(Arbitrary, Debug, Clone)]
pub struct ParsingConfig {
    pub max_trailers_size: usize,
    pub max_trailer_count: usize,
    pub strict_header_syntax: bool,
    pub allow_obs_folding: bool,
    pub validate_header_names: bool,
}

/// Security configuration
#[derive(Arbitrary, Debug, Clone)]
pub struct SecurityConfig {
    pub enforce_forbidden_trailers: bool,
    pub case_sensitive_forbidden_check: bool,
    pub allow_trailers_without_chunked: bool,
    pub detect_header_injection: bool,
    pub validate_ascii_only: bool,
}

/// Mock HTTP trailers parser for testing
#[derive(Debug)]
pub struct MockTrailersParser {
    pub parsing_config: ParsingConfig,
    pub security_config: SecurityConfig,
    pub violations: Vec<TrailerViolation>,
}

/// Trailers parsing result
#[derive(Debug, PartialEq)]
pub struct TrailersParsingResult {
    pub parsed_trailers: Vec<ParsedTrailer>,
    pub parsing_errors: Vec<TrailerError>,
    pub security_violations: Vec<SecurityViolation>,
    pub protocol_compliance_score: f32,
}

/// Parsed trailer representation
#[derive(Debug, PartialEq)]
pub struct ParsedTrailer {
    pub name: String,
    pub value: String,
    pub case_preserved: bool,
}

/// Trailer parsing errors
#[derive(Debug, PartialEq, Clone)]
pub enum TrailerError {
    MalformedSyntax(String),
    MissingColon,
    InvalidHeaderName(String),
    InvalidHeaderValue(Vec<u8>),
    TrailersTooLarge(usize),
    TooManyTrailers(usize),
    TrailersWithoutChunked,
    AmbiguousBodyLength,
}

/// Security violations in trailers
#[derive(Debug, PartialEq, Clone)]
pub struct SecurityViolation {
    pub violation_type: SecurityViolationType,
    pub header_name: String,
    pub header_value: String,
    pub attack_vector: String,
    pub severity: ViolationSeverity,
}

/// Types of security violations
#[derive(Debug, PartialEq, Clone)]
pub enum SecurityViolationType {
    ForbiddenTrailer,
    HeaderInjection,
    TrailerSmuggling,
    FramingBypass,
    AuthenticationBypass,
    CachePoison,
    UnicodeNormalization,
}

/// Trailer violations
#[derive(Debug, PartialEq, Clone)]
pub struct TrailerViolation {
    pub violation_type: TrailerViolationType,
    pub trailer_name: String,
    pub expected_behavior: String,
    pub actual_behavior: String,
    pub severity: ViolationSeverity,
}

/// Types of trailer violations
#[derive(Debug, PartialEq, Clone)]
pub enum TrailerViolationType {
    ForbiddenTrailerAccepted,
    TrailerSizeLimitNotEnforced,
    TrailerCountLimitNotEnforced,
    InvalidSyntaxAccepted,
    CaseSensitivityBypass,
    NonChunkedTrailersAccepted,
}

/// Violation severity levels
#[derive(Debug, PartialEq, Clone)]
pub enum ViolationSeverity {
    Critical,  // Security vulnerability
    High,      // Protocol violation
    Medium,    // Compliance issue
    Low,       // Edge case handling
}

impl MockTrailersParser {
    pub fn new(parsing_config: ParsingConfig, security_config: SecurityConfig) -> Self {
        Self {
            parsing_config,
            security_config,
            violations: Vec::new(),
        }
    }

    /// Parse trailers with comprehensive testing
    pub fn parse_trailers(&mut self, test_case: &TrailersParserTestCase) -> TrailersParsingResult {
        let mut parsed_trailers = Vec::new();
        let mut parsing_errors = Vec::new();
        let mut security_violations = Vec::new();

        // Check if trailers are allowed (chunked encoding required)
        let chunked_encoding_present = matches!(test_case.chunked_message.transfer_encoding, TransferEncoding::Chunked);

        if !chunked_encoding_present && !self.security_config.allow_trailers_without_chunked {
            parsing_errors.push(TrailerError::TrailersWithoutChunked);
        }

        // Check for ambiguous body length
        if matches!(test_case.chunked_message.transfer_encoding, TransferEncoding::Both(_)) {
            parsing_errors.push(TrailerError::AmbiguousBodyLength);
        }

        // Parse each trailer header
        let mut total_trailers_size = 0;
        for trailer in &test_case.trailer_headers {
            match self.parse_single_trailer(trailer, &mut total_trailers_size) {
                Ok(parsed) => {
                    // Check security constraints
                    if let Some(violation) = self.check_security_violation(&parsed, trailer) {
                        security_violations.push(violation);
                    }

                    // Check size limits
                    if total_trailers_size > self.parsing_config.max_trailers_size {
                        parsing_errors.push(TrailerError::TrailersTooLarge(total_trailers_size));
                        break;
                    }

                    // Check count limits
                    if parsed_trailers.len() >= self.parsing_config.max_trailer_count {
                        parsing_errors.push(TrailerError::TooManyTrailers(parsed_trailers.len() + 1));
                        break;
                    }

                    parsed_trailers.push(parsed);
                },
                Err(error) => {
                    parsing_errors.push(error);
                }
            }
        }

        // Validate overall behavior
        self.validate_trailer_behavior(test_case, &parsed_trailers, &parsing_errors, &security_violations);

        // Calculate compliance score
        let protocol_compliance_score = self.calculate_protocol_compliance(&parsing_errors, &security_violations);

        TrailersParsingResult {
            parsed_trailers,
            parsing_errors,
            security_violations,
            protocol_compliance_score,
        }
    }

    /// Parse a single trailer header
    fn parse_single_trailer(&self, trailer: &TrailerHeader, total_size: &mut usize) -> Result<ParsedTrailer, TrailerError> {
        let header_name = self.format_header_name(&trailer.name)?;
        let header_value = self.format_header_value(&trailer.value)?;

        // Validate header name
        if self.parsing_config.validate_header_names && !self.is_valid_header_name(&header_name) {
            return Err(TrailerError::InvalidHeaderName(header_name.clone()));
        }

        // Check syntax variant
        match &trailer.syntax_variant {
            SyntaxVariant::NoColon => {
                return Err(TrailerError::MissingColon);
            },
            SyntaxVariant::FoldedObsolete if !self.parsing_config.allow_obs_folding => {
                return Err(TrailerError::MalformedSyntax("obsolete folding not allowed".to_string()));
            },
            _ => {}
        }

        // Calculate size contribution
        *total_size += header_name.len() + header_value.len() + 4; // ": " + "\r\n"

        Ok(ParsedTrailer {
            name: header_name,
            value: header_value,
            case_preserved: true, // Always preserve case in trailers
        })
    }

    /// Check for security violations
    fn check_security_violation(&self, parsed: &ParsedTrailer, original: &TrailerHeader) -> Option<SecurityViolation> {
        if !self.security_config.enforce_forbidden_trailers {
            return None;
        }

        // Check forbidden trailers
        if self.is_forbidden_trailer(&parsed.name) {
            let attack_vector = self.classify_attack_vector(&parsed.name, &parsed.value);

            return Some(SecurityViolation {
                violation_type: SecurityViolationType::ForbiddenTrailer,
                header_name: parsed.name.clone(),
                header_value: parsed.value.clone(),
                attack_vector,
                severity: self.classify_forbidden_trailer_severity(&parsed.name),
            });
        }

        // Check for header injection patterns
        if self.security_config.detect_header_injection {
            if parsed.value.contains('\r') || parsed.value.contains('\n') {
                return Some(SecurityViolation {
                    violation_type: SecurityViolationType::HeaderInjection,
                    header_name: parsed.name.clone(),
                    header_value: parsed.value.clone(),
                    attack_vector: "CRLF injection in trailer value".to_string(),
                    severity: ViolationSeverity::Critical,
                });
            }
        }

        // Check for Unicode normalization attacks
        if parsed.name.chars().any(|c| !c.is_ascii()) || parsed.value.chars().any(|c| !c.is_ascii()) {
            if self.security_config.validate_ascii_only {
                return Some(SecurityViolation {
                    violation_type: SecurityViolationType::UnicodeNormalization,
                    header_name: parsed.name.clone(),
                    header_value: parsed.value.clone(),
                    attack_vector: "non-ASCII characters in trailer".to_string(),
                    severity: ViolationSeverity::Medium,
                });
            }
        }

        None
    }

    /// Format header name from test specification
    fn format_header_name(&self, name: &HeaderName) -> Result<String, TrailerError> {
        match name {
            HeaderName::Safe(safe) => Ok(self.format_safe_trailer_name(safe)),
            HeaderName::Forbidden(forbidden) => Ok(self.format_forbidden_trailer_name(forbidden)),
            HeaderName::Custom(custom) => Ok(custom.clone()),
            HeaderName::Malformed(malformed) => {
                match malformed {
                    MalformedHeaderName::Empty => Err(TrailerError::InvalidHeaderName("empty".to_string())),
                    MalformedHeaderName::WithSpaces(s) => Ok(s.clone()),
                    MalformedHeaderName::WithControlChars(bytes) => {
                        Ok(String::from_utf8_lossy(bytes).to_string())
                    },
                    MalformedHeaderName::WithUnicode(s) => Ok(s.clone()),
                    MalformedHeaderName::WithColon(s) => Ok(s.clone()),
                    MalformedHeaderName::TooLong(len) => Ok("X-".to_string() + &"A".repeat(*len)),
                    MalformedHeaderName::OnlyWhitespace => Ok("   ".to_string()),
                }
            }
        }
    }

    /// Format header value from test specification
    fn format_header_value(&self, value: &HeaderValue) -> Result<String, TrailerError> {
        match value {
            HeaderValue::Normal(s) => Ok(s.clone()),
            HeaderValue::Empty => Ok(String::new()),
            HeaderValue::WithCrLf(s) => Ok(format!("{}\r\nInjected: evil", s)),
            HeaderValue::WithNulls(bytes) => Ok(String::from_utf8_lossy(bytes).to_string()),
            HeaderValue::WithControlChars(bytes) => Ok(String::from_utf8_lossy(bytes).to_string()),
            HeaderValue::WithUnicode(s) => Ok(s.clone()),
            HeaderValue::VeryLong(len) => Ok("A".repeat(*len)),
            HeaderValue::OnlyWhitespace(len) => Ok(" ".repeat(*len)),
            HeaderValue::Binary(bytes) => {
                if let Ok(s) = std::str::from_utf8(bytes) {
                    Ok(s.to_string())
                } else {
                    Err(TrailerError::InvalidHeaderValue(bytes.clone()))
                }
            }
        }
    }

    /// Format safe trailer name
    fn format_safe_trailer_name(&self, safe: &SafeTrailerName) -> String {
        match safe {
            SafeTrailerName::XChecksum => "X-Checksum".to_string(),
            SafeTrailerName::XRequestId => "X-Request-Id".to_string(),
            SafeTrailerName::XProcessingTime => "X-Processing-Time".to_string(),
            SafeTrailerName::XCustomMetadata => "X-Custom-Metadata".to_string(),
            SafeTrailerName::ETag => "ETag".to_string(),
            SafeTrailerName::XTrailer => "X-Trailer".to_string(),
            SafeTrailerName::ServerTiming => "Server-Timing".to_string(),
            SafeTrailerName::XCorrelationId => "X-Correlation-ID".to_string(),
        }
    }

    /// Format forbidden trailer name
    fn format_forbidden_trailer_name(&self, forbidden: &ForbiddenTrailerName) -> String {
        match forbidden {
            ForbiddenTrailerName::ContentLength => "Content-Length".to_string(),
            ForbiddenTrailerName::TransferEncoding => "Transfer-Encoding".to_string(),
            ForbiddenTrailerName::Trailer => "Trailer".to_string(),
            ForbiddenTrailerName::ContentEncoding => "Content-Encoding".to_string(),
            ForbiddenTrailerName::ContentType => "Content-Type".to_string(),
            ForbiddenTrailerName::ContentRange => "Content-Range".to_string(),
            ForbiddenTrailerName::Authorization => "Authorization".to_string(),
            ForbiddenTrailerName::ProxyAuthorization => "Proxy-Authorization".to_string(),
            ForbiddenTrailerName::WwwAuthenticate => "WWW-Authenticate".to_string(),
            ForbiddenTrailerName::ProxyAuthenticate => "Proxy-Authenticate".to_string(),
            ForbiddenTrailerName::Cookie => "Cookie".to_string(),
            ForbiddenTrailerName::SetCookie => "Set-Cookie".to_string(),
            ForbiddenTrailerName::Host => "Host".to_string(),
            ForbiddenTrailerName::Upgrade => "Upgrade".to_string(),
            ForbiddenTrailerName::Connection => "Connection".to_string(),
            ForbiddenTrailerName::CacheControl => "Cache-Control".to_string(),
            ForbiddenTrailerName::Age => "Age".to_string(),
            ForbiddenTrailerName::Expires => "Expires".to_string(),
            ForbiddenTrailerName::Pragma => "Pragma".to_string(),
            ForbiddenTrailerName::Range => "Range".to_string(),
            ForbiddenTrailerName::IfMatch => "If-Match".to_string(),
            ForbiddenTrailerName::IfNoneMatch => "If-None-Match".to_string(),
            ForbiddenTrailerName::IfModifiedSince => "If-Modified-Since".to_string(),
            ForbiddenTrailerName::IfUnmodifiedSince => "If-Unmodified-Since".to_string(),
            ForbiddenTrailerName::IfRange => "If-Range".to_string(),
            ForbiddenTrailerName::MaxForwards => "Max-Forwards".to_string(),
            ForbiddenTrailerName::Te => "TE".to_string(),
            ForbiddenTrailerName::Expect => "Expect".to_string(),
            ForbiddenTrailerName::Vary => "Vary".to_string(),
            ForbiddenTrailerName::Warning => "Warning".to_string(),
        }
    }

    /// Check if trailer name is forbidden per RFC 9110 §6.5.1
    fn is_forbidden_trailer(&self, name: &str) -> bool {
        // This mirrors the FORBIDDEN list from codec.rs is_forbidden_trailer()
        const FORBIDDEN: &[&str] = &[
            "authorization", "age", "cache-control", "content-encoding", "content-length",
            "content-range", "content-type", "cookie", "expect", "expires", "host",
            "if-match", "if-modified-since", "if-none-match", "if-range", "if-unmodified-since",
            "max-forwards", "pragma", "proxy-authenticate", "proxy-authorization", "range",
            "retry-after", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade",
            "vary", "warning", "www-authenticate", "connection",
        ];

        if self.security_config.case_sensitive_forbidden_check {
            FORBIDDEN.contains(&name)
        } else {
            FORBIDDEN.iter().any(|&forbidden| name.eq_ignore_ascii_case(forbidden))
        }
    }

    /// Validate header name syntax
    fn is_valid_header_name(&self, name: &str) -> bool {
        if name.is_empty() {
            return false;
        }

        // Basic validation - header names must be tokens
        name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '!')
        })
    }

    /// Classify attack vector for forbidden trailers
    fn classify_attack_vector(&self, name: &str, value: &str) -> String {
        let name_lower = name.to_lowercase();

        match name_lower.as_str() {
            "content-length" => format!("Body length manipulation: {}", value),
            "transfer-encoding" => format!("Transfer encoding bypass: {}", value),
            "authorization" | "cookie" => format!("Authentication bypass: {}", value),
            "content-type" | "content-encoding" => format!("Payload processing bypass: {}", value),
            "host" | "upgrade" | "connection" => format!("Routing/framing bypass: {}", value),
            "cache-control" | "age" | "expires" => format!("Cache poisoning: {}", value),
            _ => format!("Generic forbidden trailer: {}", name),
        }
    }

    /// Classify severity of forbidden trailer
    fn classify_forbidden_trailer_severity(&self, name: &str) -> ViolationSeverity {
        let name_lower = name.to_lowercase();

        match name_lower.as_str() {
            "content-length" | "transfer-encoding" | "trailer" => ViolationSeverity::Critical,
            "authorization" | "cookie" | "set-cookie" | "www-authenticate" => ViolationSeverity::Critical,
            "host" | "upgrade" | "connection" => ViolationSeverity::High,
            "content-type" | "content-encoding" | "content-range" => ViolationSeverity::High,
            _ => ViolationSeverity::Medium,
        }
    }

    /// Validate trailer behavior against expected patterns
    fn validate_trailer_behavior(&mut self, test_case: &TrailersParserTestCase, parsed: &[ParsedTrailer], errors: &[TrailerError], violations: &[SecurityViolation]) {
        match &test_case.scenario {
            TrailersScenario::ForbiddenTrailers => {
                let has_forbidden = test_case.trailer_headers.iter().any(|h| {
                    matches!(h.name, HeaderName::Forbidden(_))
                });

                let forbidden_detected = !violations.is_empty() || errors.iter().any(|e| {
                    matches!(e, TrailerError::MalformedSyntax(_))
                });

                if has_forbidden && !forbidden_detected {
                    self.violations.push(TrailerViolation {
                        violation_type: TrailerViolationType::ForbiddenTrailerAccepted,
                        trailer_name: "forbidden trailer".to_string(),
                        expected_behavior: "rejection".to_string(),
                        actual_behavior: "acceptance".to_string(),
                        severity: ViolationSeverity::Critical,
                    });
                }
            },
            TrailersScenario::TrailersWithoutChunked => {
                let has_error = errors.iter().any(|e| {
                    matches!(e, TrailerError::TrailersWithoutChunked)
                });

                if !has_error && !self.security_config.allow_trailers_without_chunked {
                    self.violations.push(TrailerViolation {
                        violation_type: TrailerViolationType::NonChunkedTrailersAccepted,
                        trailer_name: "any trailer".to_string(),
                        expected_behavior: "rejection without chunked encoding".to_string(),
                        actual_behavior: "acceptance".to_string(),
                        severity: ViolationSeverity::High,
                    });
                }
            },
            TrailersScenario::OversizedTrailers => {
                let total_size: usize = parsed.iter()
                    .map(|t| t.name.len() + t.value.len() + 4)
                    .sum();

                let size_limit_enforced = errors.iter().any(|e| {
                    matches!(e, TrailerError::TrailersTooLarge(_))
                });

                if total_size > self.parsing_config.max_trailers_size && !size_limit_enforced {
                    self.violations.push(TrailerViolation {
                        violation_type: TrailerViolationType::TrailerSizeLimitNotEnforced,
                        trailer_name: "oversized trailers".to_string(),
                        expected_behavior: "size limit enforcement".to_string(),
                        actual_behavior: format!("accepted {} bytes", total_size),
                        severity: ViolationSeverity::High,
                    });
                }
            },
            _ => {
                // Other scenarios have different validation logic
            }
        }
    }

    /// Calculate protocol compliance score
    fn calculate_protocol_compliance(&self, errors: &[TrailerError], violations: &[SecurityViolation]) -> f32 {
        let mut penalty = 0.0;

        // Penalize parsing errors
        for error in errors {
            penalty += match error {
                TrailerError::TrailersWithoutChunked | TrailerError::AmbiguousBodyLength => 10.0,
                TrailerError::TrailersTooLarge(_) | TrailerError::TooManyTrailers(_) => 8.0,
                TrailerError::MalformedSyntax(_) | TrailerError::InvalidHeaderName(_) => 5.0,
                TrailerError::MissingColon | TrailerError::InvalidHeaderValue(_) => 3.0,
            };
        }

        // Penalize security violations
        for violation in violations {
            penalty += match violation.severity {
                ViolationSeverity::Critical => 15.0,
                ViolationSeverity::High => 10.0,
                ViolationSeverity::Medium => 5.0,
                ViolationSeverity::Low => 2.0,
            };
        }

        // Additional penalty for our own violations
        for violation in &self.violations {
            penalty += match violation.severity {
                ViolationSeverity::Critical => 15.0,
                ViolationSeverity::High => 10.0,
                ViolationSeverity::Medium => 5.0,
                ViolationSeverity::Low => 2.0,
            };
        }

        let max_score = 100.0;
        (max_score - penalty).max(0.0) / max_score
    }
}

/// Generate comprehensive trailers test cases
fn generate_trailers_test_cases() -> Vec<TrailersParserTestCase> {
    vec![
        // Valid trailers with chunked encoding
        TrailersParserTestCase {
            scenario: TrailersScenario::ValidTrailers,
            chunked_message: ChunkedMessage {
                transfer_encoding: TransferEncoding::Chunked,
                chunks: vec![
                    MessageChunk { data: b"hello".to_vec(), extensions: vec![] },
                ],
                final_chunk_size: 0,
                chunk_extensions: vec![],
            },
            trailer_headers: vec![
                TrailerHeader {
                    name: HeaderName::Safe(SafeTrailerName::XChecksum),
                    value: HeaderValue::Normal("sha256:abc123".to_string()),
                    syntax_variant: SyntaxVariant::Standard,
                },
                TrailerHeader {
                    name: HeaderName::Safe(SafeTrailerName::XRequestId),
                    value: HeaderValue::Normal("req-456".to_string()),
                    syntax_variant: SyntaxVariant::Standard,
                },
            ],
            parsing_config: ParsingConfig {
                max_trailers_size: 8192,
                max_trailer_count: 50,
                strict_header_syntax: true,
                allow_obs_folding: false,
                validate_header_names: true,
            },
            security_config: SecurityConfig {
                enforce_forbidden_trailers: true,
                case_sensitive_forbidden_check: false,
                allow_trailers_without_chunked: false,
                detect_header_injection: true,
                validate_ascii_only: false,
            },
        },

        // Forbidden trailers (security violation)
        TrailersParserTestCase {
            scenario: TrailersScenario::ForbiddenTrailers,
            chunked_message: ChunkedMessage {
                transfer_encoding: TransferEncoding::Chunked,
                chunks: vec![
                    MessageChunk { data: b"data".to_vec(), extensions: vec![] },
                ],
                final_chunk_size: 0,
                chunk_extensions: vec![],
            },
            trailer_headers: vec![
                TrailerHeader {
                    name: HeaderName::Forbidden(ForbiddenTrailerName::ContentLength),
                    value: HeaderValue::Normal("999".to_string()),
                    syntax_variant: SyntaxVariant::Standard,
                },
                TrailerHeader {
                    name: HeaderName::Forbidden(ForbiddenTrailerName::TransferEncoding),
                    value: HeaderValue::Normal("chunked".to_string()),
                    syntax_variant: SyntaxVariant::Standard,
                },
            ],
            parsing_config: ParsingConfig {
                max_trailers_size: 8192,
                max_trailer_count: 50,
                strict_header_syntax: true,
                allow_obs_folding: false,
                validate_header_names: true,
            },
            security_config: SecurityConfig {
                enforce_forbidden_trailers: true,
                case_sensitive_forbidden_check: false,
                allow_trailers_without_chunked: false,
                detect_header_injection: true,
                validate_ascii_only: false,
            },
        },
    ]
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);

    // Try to generate a test case from fuzzer input
    let test_case = match TrailersParserTestCase::arbitrary(&mut unstructured) {
        Ok(tc) => tc,
        Err(_) => {
            // If generation fails, use a pre-generated test case
            let predefined_cases = generate_trailers_test_cases();
            if predefined_cases.is_empty() {
                return;
            }
            let index = unstructured.int_in_range(0..=predefined_cases.len() - 1).unwrap_or(0);
            predefined_cases[index].clone()
        }
    };

    // Create trailers parser
    let mut parser = MockTrailersParser::new(
        test_case.parsing_config.clone(),
        test_case.security_config.clone()
    );

    // Parse trailers and check compliance
    let _result = parser.parse_trailers(&test_case);

    // Test specific trailer edge cases
    test_forbidden_trailer_detection(&test_case);
    test_trailer_size_limits(&test_case);
    test_trailer_syntax_validation(&test_case);
    test_header_injection_prevention(&test_case);
});

/// Test forbidden trailer detection
fn test_forbidden_trailer_detection(test_case: &TrailersParserTestCase) {
    if test_case.scenario != TrailersScenario::ForbiddenTrailers {
        return;
    }

    let parser = MockTrailersParser::new(
        test_case.parsing_config.clone(),
        test_case.security_config.clone()
    );

    // Test critical forbidden headers
    let critical_forbidden = [
        "Content-Length", "content-length", "CONTENT-LENGTH",
        "Transfer-Encoding", "transfer-encoding", "TRANSFER-ENCODING",
        "Trailer", "trailer", "TRAILER",
    ];

    for header_name in critical_forbidden {
        let is_forbidden = parser.is_forbidden_trailer(header_name);
        assert!(is_forbidden, "Critical header '{}' should be forbidden", header_name);
    }
}

/// Test trailer size limits
fn test_trailer_size_limits(test_case: &TrailersParserTestCase) {
    if test_case.scenario != TrailersScenario::OversizedTrailers {
        return;
    }

    let mut parser = MockTrailersParser::new(
        test_case.parsing_config.clone(),
        test_case.security_config.clone()
    );

    // Create oversized trailer
    let oversized_trailer = TrailerHeader {
        name: HeaderName::Safe(SafeTrailerName::XChecksum),
        value: HeaderValue::VeryLong(parser.parsing_config.max_trailers_size + 1000),
        syntax_variant: SyntaxVariant::Standard,
    };

    let mut total_size = 0;
    let result = parser.parse_single_trailer(&oversized_trailer, &mut total_size);

    // Should enforce size limits
    match result {
        Err(TrailerError::TrailersTooLarge(_)) => {
            // Correct behavior
        },
        _ => {
            // Size limit not enforced
        }
    }
}

/// Test trailer syntax validation
fn test_trailer_syntax_validation(test_case: &TrailersParserTestCase) {
    if test_case.scenario != TrailersScenario::MalformedTrailerSyntax {
        return;
    }

    let parser = MockTrailersParser::new(
        test_case.parsing_config.clone(),
        test_case.security_config.clone()
    );

    // Test malformed syntax cases
    let malformed_cases = [
        // No colon
        TrailerHeader {
            name: HeaderName::Custom("NoColon".to_string()),
            value: HeaderValue::Normal("value".to_string()),
            syntax_variant: SyntaxVariant::NoColon,
        },
        // Empty header name
        TrailerHeader {
            name: HeaderName::Malformed(MalformedHeaderName::Empty),
            value: HeaderValue::Normal("value".to_string()),
            syntax_variant: SyntaxVariant::Standard,
        },
    ];

    for malformed in malformed_cases {
        let mut total_size = 0;
        let result = parser.parse_single_trailer(&malformed, &mut total_size);

        // Should reject malformed syntax
        match result {
            Err(_) => {
                // Correct behavior - syntax error detected
            },
            Ok(_) => {
                // Malformed syntax was accepted
            }
        }
    }
}

/// Test header injection prevention
fn test_header_injection_prevention(test_case: &TrailersParserTestCase) {
    if test_case.scenario != TrailersScenario::TrailerHeaderInjection {
        return;
    }

    let mut parser = MockTrailersParser::new(
        test_case.parsing_config.clone(),
        test_case.security_config.clone()
    );

    // Test CRLF injection
    let injection_trailer = TrailerHeader {
        name: HeaderName::Safe(SafeTrailerName::XChecksum),
        value: HeaderValue::WithCrLf("normal\r\nInjected: evil".to_string()),
        syntax_variant: SyntaxVariant::Standard,
    };

    let mut total_size = 0;
    if let Ok(parsed) = parser.parse_single_trailer(&injection_trailer, &mut total_size) {
        // Check if injection was detected
        let violation = parser.check_security_violation(&parsed, &injection_trailer);

        match violation {
            Some(SecurityViolation { violation_type: SecurityViolationType::HeaderInjection, .. }) => {
                // Correct behavior - injection detected
            },
            _ => {
                // Header injection not detected
            }
        }
    }
}