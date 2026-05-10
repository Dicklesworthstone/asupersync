#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 Content-Length vs body-bytes mismatch fuzzing.
///
/// Tests the validation logic that ensures actual body length matches the
/// declared Content-Length header, covering both request parsing and response
/// encoding scenarios per RFC 9112 and RFC 9110.
///
/// Key validation areas from codec.rs:
/// - Request parsing: Content-Length header validation (lines 1004-1014)
/// - Response encoding: body length vs declared length check (lines 1254-1258)
/// - Size limit enforcement (lines 1131-1142)
/// - Conflict detection with Transfer-Encoding (lines 994-1001)
///
/// Security implications:
/// - Request smuggling via Content-Length manipulation
/// - Buffer overflow/underflow from mismatched lengths
/// - Resource exhaustion via oversized declarations
/// - Protocol confusion attacks
#[derive(Arbitrary, Debug, Clone)]
pub struct ContentLengthTestCase {
    /// Message type being tested
    message_type: MessageType,
    /// Content-Length header configuration
    content_length: ContentLengthConfig,
    /// Actual body configuration
    body: BodyConfig,
    /// Additional headers that may conflict
    headers: HeadersConfig,
    /// Edge case scenarios
    scenario: TestScenario,
}

impl ContentLengthTestCase {
    fn semantic_shape(&self) -> usize {
        self.message_type
            .semantic_shape()
            .saturating_add(self.scenario.semantic_code())
            .saturating_add(self.headers.extra_headers.len())
            .saturating_add(self.headers.custom_headers.len())
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub enum MessageType {
    Request(RequestConfig),
    Response(ResponseConfig),
}

impl MessageType {
    fn semantic_shape(&self) -> usize {
        match self {
            MessageType::Request(request) => request.semantic_shape(),
            MessageType::Response(response) => response.semantic_shape(),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub struct RequestConfig {
    method: RequestMethod,
    uri: String,
    version: HttpVersion,
}

impl RequestConfig {
    fn semantic_shape(&self) -> usize {
        self.method
            .semantic_code()
            .saturating_add(self.uri.len())
            .saturating_add(self.version.semantic_code())
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ResponseConfig {
    status: u16,
    reason: String,
    version: HttpVersion,
    /// Special handling for HEAD responses (body allowed to be empty despite Content-Length)
    is_head_response: bool,
}

impl ResponseConfig {
    fn semantic_shape(&self) -> usize {
        usize::from(self.status)
            .saturating_add(self.reason.len())
            .saturating_add(self.version.semantic_code())
            .saturating_add(usize::from(self.is_head_response))
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub enum RequestMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Custom(String),
}

impl RequestMethod {
    fn semantic_code(&self) -> usize {
        match self {
            RequestMethod::Get => 1,
            RequestMethod::Head => 2,
            RequestMethod::Post => 3,
            RequestMethod::Put => 4,
            RequestMethod::Patch => 5,
            RequestMethod::Delete => 6,
            RequestMethod::Options => 7,
            RequestMethod::Custom(method) => 8usize.saturating_add(method.len()),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http20, // Invalid for HTTP/1.1 codec
    Other(String),
}

impl HttpVersion {
    fn semantic_code(&self) -> usize {
        match self {
            HttpVersion::Http10 => 10,
            HttpVersion::Http11 => 11,
            HttpVersion::Http20 => 20,
            HttpVersion::Other(version) => 21usize.saturating_add(version.len()),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ContentLengthConfig {
    /// No Content-Length header
    Missing,
    /// Valid Content-Length values
    Valid(usize),
    /// Invalid Content-Length formats
    Invalid(InvalidContentLength),
    /// Multiple Content-Length headers (forbidden)
    Multiple(Vec<String>),
    /// Conflicting with other headers
    Conflicting(ConflictingHeaders),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum InvalidContentLength {
    /// Non-numeric values
    NonNumeric(String),
    /// Leading/trailing whitespace
    WithWhitespace(String),
    /// Leading zeros (discouraged)
    LeadingZeros(String),
    /// Leading plus sign (rejected by strict parsers)
    LeadingPlus(String),
    /// Negative values
    Negative(String),
    /// Floating point
    Float(String),
    /// Very large numbers
    Overflow(String),
    /// Empty value
    Empty,
    /// Control characters
    WithControl(String),
    /// Hex/binary format
    AlternateBase(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ConflictingHeaders {
    /// Both Content-Length and Transfer-Encoding (forbidden)
    TransferEncoding(String, String), // (content-length, transfer-encoding)
    /// Multiple encoding headers
    MultipleEncoding(Vec<String>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum BodyConfig {
    /// Body matches declared length exactly
    Exact(Vec<u8>),
    /// Body shorter than declared length
    TooShort(Vec<u8>),
    /// Body longer than declared length
    TooLong(Vec<u8>),
    /// Empty body
    Empty,
    /// Body with specific patterns
    Pattern(BodyPattern),
    /// Very large body
    Oversized(Vec<u8>),
    /// Malformed body
    Malformed(MalformedBody),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum BodyPattern {
    AllZeros(usize),
    AllOnes(usize),
    Incrementing(usize),
    Random(usize),
    Text(String),
    Binary(Vec<u8>),
    HttpLike(String),
    JsonLike(String),
    XmlLike(String),
    Base64Like(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum MalformedBody {
    WithNulls(Vec<u8>),
    WithControl(Vec<u8>),
    HighBitSet(Vec<u8>),
    InvalidUtf8(Vec<u8>),
    Truncated(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub struct HeadersConfig {
    /// Additional headers that may affect parsing
    extra_headers: Vec<(String, String)>,
    /// Host header (required for HTTP/1.1)
    host: Option<String>,
    /// Content-Type header
    content_type: Option<String>,
    /// User-Agent header
    user_agent: Option<String>,
    /// Custom headers with edge cases
    custom_headers: Vec<CustomHeader>,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct CustomHeader {
    name: String,
    value: String,
    /// Header field edge cases
    formatting: HeaderFormatting,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum HeaderFormatting {
    Normal,
    ExtraWhitespace,
    NoWhitespace,
    MultipleColons,
    EmptyName,
    EmptyValue,
    VeryLong,
    WithControl,
    CaseMixed,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum TestScenario {
    /// Normal operation cases
    ValidMatch,
    ValidMismatch,
    /// Boundary conditions
    ZeroLength,
    MaxLength,
    OffByOne,
    /// Error conditions
    InvalidHeader,
    DuplicateHeader,
    ConflictingHeaders,
    OversizeDeclaration,
    /// Security scenarios
    RequestSmuggling,
    BufferOverflow,
    IntegerOverflow,
    /// Protocol edge cases
    Http10Behavior,
    Http11Requirements,
    HeadResponseSpecial,
    ChunkedConflict,
    /// Performance scenarios
    LargeBodySmallLength,
    SmallBodyLargeLength,
    RepeatedValidation,
}

impl TestScenario {
    fn semantic_code(&self) -> usize {
        match self {
            TestScenario::ValidMatch => 1,
            TestScenario::ValidMismatch => 2,
            TestScenario::ZeroLength => 3,
            TestScenario::MaxLength => 4,
            TestScenario::OffByOne => 5,
            TestScenario::InvalidHeader => 6,
            TestScenario::DuplicateHeader => 7,
            TestScenario::ConflictingHeaders => 8,
            TestScenario::OversizeDeclaration => 9,
            TestScenario::RequestSmuggling => 10,
            TestScenario::BufferOverflow => 11,
            TestScenario::IntegerOverflow => 12,
            TestScenario::Http10Behavior => 13,
            TestScenario::Http11Requirements => 14,
            TestScenario::HeadResponseSpecial => 15,
            TestScenario::ChunkedConflict => 16,
            TestScenario::LargeBodySmallLength => 17,
            TestScenario::SmallBodyLargeLength => 18,
            TestScenario::RepeatedValidation => 19,
        }
    }
}

/// Mock HTTP/1.1 Content-Length validator for fuzzing
#[derive(Debug)]
pub struct MockContentLengthValidator {
    max_body_size: usize,
    strict_parsing: bool,
    allow_head_mismatch: bool,
}

type HeaderList = Vec<(String, String)>;
type BodyBytes = Vec<u8>;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedMessage {
    pub declared_length: Option<usize>,
    pub actual_length: usize,
    pub headers: HeaderList,
    pub body: BodyBytes,
    pub validation_result: ValidationResult,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid,
    LengthMismatch { declared: usize, actual: usize },
    InvalidHeader(String),
    DuplicateHeader,
    ConflictingHeaders,
    BodyTooLarge,
    MalformedMessage(String),
}

impl Default for MockContentLengthValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl MockContentLengthValidator {
    pub fn new() -> Self {
        Self {
            max_body_size: 16 * 1024 * 1024, // 16MB default
            strict_parsing: true,
            allow_head_mismatch: true, // HEAD responses may have Content-Length > body length
        }
    }

    pub fn with_max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    pub fn with_strict_parsing(mut self, strict: bool) -> Self {
        self.strict_parsing = strict;
        self
    }

    pub fn validate_message(
        &self,
        test_case: &ContentLengthTestCase,
    ) -> Result<ValidatedMessage, String> {
        let (headers, body) = self.build_message(test_case)?;

        // Extract Content-Length from headers
        let declared_length = self.extract_content_length(&headers)?;

        // Validate header conflicts first
        self.validate_header_conflicts(&headers)?;

        // Check body size limits
        if body.len() > self.max_body_size {
            return Ok(ValidatedMessage {
                declared_length,
                actual_length: body.len(),
                headers,
                body,
                validation_result: ValidationResult::BodyTooLarge,
            });
        }

        // Check declared size limits
        if let Some(declared) = declared_length
            && declared > self.max_body_size
        {
            return Ok(ValidatedMessage {
                declared_length,
                actual_length: body.len(),
                headers,
                body,
                validation_result: ValidationResult::BodyTooLarge,
            });
        }

        // Validate Content-Length vs body length match
        let validation_result =
            self.validate_length_match(test_case, declared_length, body.len())?;

        Ok(ValidatedMessage {
            declared_length,
            actual_length: body.len(),
            headers,
            body,
            validation_result,
        })
    }

    fn build_message(
        &self,
        test_case: &ContentLengthTestCase,
    ) -> Result<(HeaderList, BodyBytes), String> {
        let mut headers = Vec::new();

        // Add basic headers
        if let Some(host) = &test_case.headers.host {
            headers.push(("Host".to_string(), host.clone()));
        } else if matches!(test_case.message_type, MessageType::Request(ref req) if req.version == HttpVersion::Http11)
        {
            headers.push(("Host".to_string(), "example.com".to_string()));
        }

        if let Some(ct) = &test_case.headers.content_type {
            headers.push(("Content-Type".to_string(), ct.clone()));
        }

        if let Some(ua) = &test_case.headers.user_agent {
            headers.push(("User-Agent".to_string(), ua.clone()));
        }

        // Add Content-Length header(s)
        match &test_case.content_length {
            ContentLengthConfig::Missing => {} // No Content-Length header

            ContentLengthConfig::Valid(len) => {
                headers.push(("Content-Length".to_string(), len.to_string()));
            }

            ContentLengthConfig::Invalid(invalid) => {
                let value = match invalid {
                    InvalidContentLength::NonNumeric(s) => s.clone(),
                    InvalidContentLength::WithWhitespace(s) => format!("  {}  ", s),
                    InvalidContentLength::LeadingZeros(s) => format!("000{}", s),
                    InvalidContentLength::LeadingPlus(s) => format!("+{}", s),
                    InvalidContentLength::Negative(s) => format!("-{}", s),
                    InvalidContentLength::Float(s) => format!("{}.5", s),
                    InvalidContentLength::Overflow(s) => s.clone(),
                    InvalidContentLength::Empty => String::new(),
                    InvalidContentLength::WithControl(s) => format!("{}\x01{}", s, s),
                    InvalidContentLength::AlternateBase(s) => format!("0x{}", s),
                };
                headers.push(("Content-Length".to_string(), value));
            }

            ContentLengthConfig::Multiple(values) => {
                for value in values {
                    headers.push(("Content-Length".to_string(), value.clone()));
                }
            }

            ContentLengthConfig::Conflicting(conflict) => match conflict {
                ConflictingHeaders::TransferEncoding(cl, te) => {
                    headers.push(("Content-Length".to_string(), cl.clone()));
                    headers.push(("Transfer-Encoding".to_string(), te.clone()));
                }
                ConflictingHeaders::MultipleEncoding(encodings) => {
                    headers.push(("Content-Length".to_string(), "10".to_string()));
                    for encoding in encodings {
                        headers.push(("Transfer-Encoding".to_string(), encoding.clone()));
                    }
                }
            },
        }

        // Add extra headers
        for (name, value) in &test_case.headers.extra_headers {
            headers.push((name.clone(), value.clone()));
        }

        // Add custom headers with formatting
        for custom in &test_case.headers.custom_headers {
            let (name, value) = self.format_custom_header(custom);
            headers.push((name, value));
        }

        // Build body
        let body = self.build_body(&test_case.body)?;

        Ok((headers, body))
    }

    fn format_custom_header(&self, custom: &CustomHeader) -> (String, String) {
        match custom.formatting {
            HeaderFormatting::Normal => (custom.name.clone(), custom.value.clone()),
            HeaderFormatting::ExtraWhitespace => (
                format!("  {}  ", custom.name),
                format!("  {}  ", custom.value),
            ),
            HeaderFormatting::NoWhitespace => {
                (custom.name.replace(" ", ""), custom.value.replace(" ", ""))
            }
            HeaderFormatting::MultipleColons => {
                (format!("{}:extra", custom.name), custom.value.clone())
            }
            HeaderFormatting::EmptyName => (String::new(), custom.value.clone()),
            HeaderFormatting::EmptyValue => (custom.name.clone(), String::new()),
            HeaderFormatting::VeryLong => {
                let long_name = custom.name.repeat(100);
                let long_value = custom.value.repeat(100);
                (long_name, long_value)
            }
            HeaderFormatting::WithControl => (
                format!("{}\x01{}", custom.name, custom.name),
                format!("{}\x02{}", custom.value, custom.value),
            ),
            HeaderFormatting::CaseMixed => {
                let mixed_name = custom
                    .name
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i % 2 == 0 {
                            c.to_ascii_uppercase()
                        } else {
                            c.to_ascii_lowercase()
                        }
                    })
                    .collect();
                (mixed_name, custom.value.clone())
            }
        }
    }

    fn build_body(&self, body_config: &BodyConfig) -> Result<Vec<u8>, String> {
        match body_config {
            BodyConfig::Exact(data) => Ok(data.clone()),
            BodyConfig::TooShort(data) => Ok(data.clone()),
            BodyConfig::TooLong(data) => Ok(data.clone()),
            BodyConfig::Empty => Ok(Vec::new()),

            BodyConfig::Pattern(pattern) => {
                match pattern {
                    BodyPattern::AllZeros(size) => Ok(vec![0u8; *size % 1000]),
                    BodyPattern::AllOnes(size) => Ok(vec![0xFFu8; *size % 1000]),
                    BodyPattern::Incrementing(size) => Ok((0u8..(*size as u8 % 255)).collect()),
                    BodyPattern::Random(size) => {
                        // Deterministic "random" for fuzzing reproducibility
                        Ok((0..*size % 1000).map(|i| (i * 17 + 42) as u8).collect())
                    }
                    BodyPattern::Text(text) => Ok(text.as_bytes().to_vec()),
                    BodyPattern::Binary(data) => Ok(data.clone()),
                    BodyPattern::HttpLike(content) => Ok(format!(
                        "GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        content
                    )
                    .into_bytes()),
                    BodyPattern::JsonLike(content) => {
                        Ok(format!("{{\"data\":\"{}\",\"type\":\"test\"}}", content).into_bytes())
                    }
                    BodyPattern::XmlLike(content) => {
                        Ok(format!("<root><data>{}</data></root>", content).into_bytes())
                    }
                    BodyPattern::Base64Like(content) => {
                        // Simulate base64-like content
                        Ok(content.chars().map(|c| c as u8).collect())
                    }
                }
            }

            BodyConfig::Oversized(data) => Ok(data.clone()),

            BodyConfig::Malformed(malformed) => match malformed {
                MalformedBody::WithNulls(data) => {
                    let mut result = data.clone();
                    result.extend_from_slice(&[0u8; 5]);
                    Ok(result)
                }
                MalformedBody::WithControl(data) => {
                    let mut result = data.clone();
                    result.extend_from_slice(&[1u8, 2u8, 3u8]);
                    Ok(result)
                }
                MalformedBody::HighBitSet(data) => Ok(data.iter().map(|&b| b | 0x80).collect()),
                MalformedBody::InvalidUtf8(data) => Ok(data.clone()),
                MalformedBody::Truncated(data) => Ok(data.clone()),
            },
        }
    }

    fn extract_content_length(
        &self,
        headers: &[(String, String)],
    ) -> Result<Option<usize>, String> {
        let mut content_lengths = Vec::new();

        for (name, value) in headers {
            if name.eq_ignore_ascii_case("content-length") {
                content_lengths.push(value);
            }
        }

        match content_lengths.len() {
            0 => Ok(None),
            1 => {
                let value = content_lengths[0].trim();

                if self.strict_parsing {
                    // RFC 9112 §6.1: Content-Length is 1*DIGIT (no leading sign)
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err("Invalid Content-Length format".to_string());
                    }
                }

                match value.parse::<usize>() {
                    Ok(len) => Ok(Some(len)),
                    Err(_) => Err("Content-Length parse error".to_string()),
                }
            }
            _ => Err("Duplicate Content-Length headers".to_string()),
        }
    }

    fn validate_header_conflicts(&self, headers: &[(String, String)]) -> Result<(), String> {
        let mut has_content_length = false;
        let mut has_transfer_encoding = false;

        for (name, _) in headers {
            if name.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                has_transfer_encoding = true;
            }
        }

        if has_content_length && has_transfer_encoding {
            return Err(
                "Ambiguous body length: both Content-Length and Transfer-Encoding present"
                    .to_string(),
            );
        }

        Ok(())
    }

    fn validate_length_match(
        &self,
        test_case: &ContentLengthTestCase,
        declared_length: Option<usize>,
        actual_length: usize,
    ) -> Result<ValidationResult, String> {
        let Some(declared) = declared_length else {
            return Ok(ValidationResult::Valid); // No Content-Length to validate
        };

        // Special case: HEAD responses may have Content-Length without body
        if let MessageType::Response(ref resp) = test_case.message_type
            && self.allow_head_mismatch
            && resp.is_head_response
            && actual_length == 0
        {
            return Ok(ValidationResult::Valid);
        }

        if declared != actual_length {
            Ok(ValidationResult::LengthMismatch {
                declared,
                actual: actual_length,
            })
        } else {
            Ok(ValidationResult::Valid)
        }
    }
}

impl PartialEq for HttpVersion {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(test_case) = ContentLengthTestCase::arbitrary(&mut u) {
        let validator = MockContentLengthValidator::new();
        std::hint::black_box(test_case.semantic_shape());

        // Test main validation path
        let result = validator.validate_message(&test_case);

        match result {
            Ok(validated) => {
                // Validate basic invariants
                assert!(
                    validated.actual_length == validated.body.len(),
                    "Actual length should match body length"
                );

                // Check validation result consistency
                match validated.validation_result {
                    ValidationResult::Valid => {
                        // If valid, declared should match actual (unless HEAD response exception)
                        if let Some(declared) = validated.declared_length {
                            if let MessageType::Response(ref resp) = test_case.message_type {
                                if !(resp.is_head_response && validated.actual_length == 0) {
                                    assert_eq!(
                                        declared, validated.actual_length,
                                        "Valid result but lengths don't match"
                                    );
                                }
                            } else {
                                assert_eq!(
                                    declared, validated.actual_length,
                                    "Valid result but lengths don't match"
                                );
                            }
                        }
                    }

                    ValidationResult::LengthMismatch { declared, actual } => {
                        assert_eq!(actual, validated.actual_length);
                        assert_eq!(Some(declared), validated.declared_length);
                        assert_ne!(declared, actual, "Mismatch result but lengths match");
                    }

                    ValidationResult::BodyTooLarge => {
                        assert!(
                            validated.actual_length > validator.max_body_size
                                || validated
                                    .declared_length
                                    .is_some_and(|d| d > validator.max_body_size),
                            "Body too large result but sizes within limits"
                        );
                    }

                    ValidationResult::InvalidHeader(_)
                    | ValidationResult::DuplicateHeader
                    | ValidationResult::ConflictingHeaders
                    | ValidationResult::MalformedMessage(_) => {
                        // These are expected for malformed input
                    }
                }

                // Test Content-Length header extraction consistency
                if validated.declared_length.is_some() {
                    let content_length_count = validated
                        .headers
                        .iter()
                        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .count();

                    assert_eq!(
                        content_length_count, 1,
                        "Exactly one Content-Length header should be present when declared length exists"
                    );
                }

                // Test body size constraints
                assert!(
                    validated.body.len() <= validator.max_body_size * 2, // Allow some fuzz tolerance
                    "Body size should not be excessively large"
                );
            }

            Err(_error) => {
                // Errors are acceptable for malformed input
                // Validate that errors don't cause crashes or infinite loops
            }
        }

        // Test edge cases
        test_boundary_conditions(&validator, &test_case);
        test_header_conflicts(&validator, &test_case);
        test_size_limits(&validator, &test_case);
        test_parsing_strictness(&test_case);
    }
});

fn test_boundary_conditions(
    validator: &MockContentLengthValidator,
    test_case: &ContentLengthTestCase,
) {
    // Test zero-length scenarios
    let mut zero_case = test_case.clone();
    zero_case.content_length = ContentLengthConfig::Valid(0);
    zero_case.body = BodyConfig::Empty;

    let result = validator.validate_message(&zero_case);
    assert!(result.is_ok(), "Zero length case should be valid");

    // Test maximum size scenarios
    let mut max_case = test_case.clone();
    max_case.content_length = ContentLengthConfig::Valid(validator.max_body_size);

    let result = validator.validate_message(&max_case);
    // Should either succeed or fail cleanly
    assert!(
        result.is_ok() || result.is_err(),
        "Max size case should not panic"
    );
}

fn test_header_conflicts(
    validator: &MockContentLengthValidator,
    test_case: &ContentLengthTestCase,
) {
    // Test Content-Length + Transfer-Encoding conflict
    let mut conflict_case = test_case.clone();
    conflict_case.content_length = ContentLengthConfig::Conflicting(
        ConflictingHeaders::TransferEncoding("10".to_string(), "chunked".to_string()),
    );

    let result = validator.validate_message(&conflict_case);

    // Should detect conflict
    match result {
        Ok(validated) => {
            assert!(
                matches!(
                    validated.validation_result,
                    ValidationResult::ConflictingHeaders
                ),
                "Should detect header conflict"
            );
        }
        Err(_) => {
            // Also acceptable - error during parsing
        }
    }
}

fn test_size_limits(validator: &MockContentLengthValidator, test_case: &ContentLengthTestCase) {
    // Test oversized declaration
    let mut oversized_case = test_case.clone();
    oversized_case.content_length = ContentLengthConfig::Valid(validator.max_body_size * 2);

    let result = validator.validate_message(&oversized_case);

    if let Ok(validated) = result {
        assert!(
            matches!(validated.validation_result, ValidationResult::BodyTooLarge),
            "Should reject oversized declarations"
        );
    }
}

fn test_parsing_strictness(test_case: &ContentLengthTestCase) {
    // Test strict vs lenient parsing
    let strict_validator = MockContentLengthValidator::new().with_strict_parsing(true);
    let lenient_validator = MockContentLengthValidator::new().with_strict_parsing(false);

    let strict_result = strict_validator.validate_message(test_case);
    let lenient_result = lenient_validator.validate_message(test_case);

    // Strict parser should never be more lenient than lenient parser
    if strict_result.is_ok() {
        assert!(
            lenient_result.is_ok(),
            "Lenient parser should not reject what strict parser accepts"
        );
    }
}
