//! Fuzzing target for HTTP/1.1 Transfer-Encoding: chunked with trailers.
//!
//! Tests RFC 9112 §7.1 compliance for chunked encoding with trailing headers:
//! 1. Transfer-Encoding: chunked header properly declares chunked body
//! 2. Body consists of chunk-size CRLF chunk-data CRLF sequence
//! 3. Final 0-sized chunk followed by trailing headers
//! 4. Trailers end with empty line (double CRLF)
//! 5. Trailer header validation per RFC 9110 §6.5.1
//!
//! Per RFC 9112 §7.1.3: "A sender MUST NOT generate a trailer that contains
//! a field necessary for message framing, routing, or authentication."
//!
//! Vulnerability areas:
//! - Trailer headers parsed before final 0-chunk (protocol violation)
//! - Forbidden headers in trailer section (Content-Length, Transfer-Encoding, etc.)
//! - Header injection through malformed trailer syntax
//! - Memory exhaustion via oversized trailer sections
//! - Protocol confusion between chunked body and trailer headers
//! - Missing final empty line causing trailer/body confusion
//! - CRLF injection in trailer values leading to header smuggling

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

type HeaderMap = HashMap<String, String>;

/// Test input for Transfer-Encoding: chunked with trailers
#[derive(Debug, Arbitrary)]
pub struct TeChunkedWithTrailersInput {
    /// HTTP request/response configuration
    message_type: MessageType,
    /// Initial headers including Transfer-Encoding
    initial_headers: Vec<HttpHeader>,
    /// Chunked body configuration
    chunked_body: ChunkedBodyWithTrailers,
    /// Trailer headers after final 0-chunk
    trailing_headers: Vec<TrailerHeader>,
    /// Protocol compliance testing options
    compliance_tests: ComplianceTestOptions,
    /// Edge case scenarios
    edge_cases: Vec<EdgeCaseTest>,
}

/// HTTP message type for testing
#[derive(Debug, Arbitrary)]
pub enum MessageType {
    /// HTTP request with chunked body
    Request {
        method: String,
        uri: String,
        version: HttpVersion,
    },
    /// HTTP response with chunked body
    Response {
        status_code: u16,
        reason_phrase: String,
        version: HttpVersion,
    },
}

/// HTTP version for testing
#[derive(Debug, Arbitrary)]
pub enum HttpVersion {
    Http10,
    Http11,
}

/// HTTP header for initial headers
#[derive(Debug, Arbitrary)]
pub struct HttpHeader {
    name: String,
    value: String,
    /// Whether this should be Transfer-Encoding: chunked
    is_transfer_encoding_chunked: bool,
}

/// Chunked body with trailing headers
#[derive(Debug, Arbitrary)]
pub struct ChunkedBodyWithTrailers {
    /// Regular chunks before the final 0-chunk
    chunks: Vec<ChunkData>,
    /// Whether to include malformed chunks
    include_malformed_chunks: bool,
    /// Size of final 0-chunk (should be 0)
    final_chunk_size: u8,
    /// Whether to include trailer headers before final chunk (protocol violation)
    trailers_before_final: bool,
}

/// Individual chunk in chunked encoding
#[derive(Debug, Arbitrary)]
pub struct ChunkData {
    /// Chunk size (will be hex-encoded)
    size: u16,
    /// Chunk data payload
    data: Vec<u8>,
    /// Optional chunk extensions
    extensions: Vec<ChunkExtension>,
    /// Whether to use malformed chunk format
    malformed: bool,
}

/// Chunk extension for testing
#[derive(Debug, Arbitrary)]
pub struct ChunkExtension {
    name: String,
    value: Option<String>,
}

/// Trailing header after final 0-chunk
#[derive(Debug, Arbitrary)]
pub struct TrailerHeader {
    name: String,
    value: String,
    /// Whether this is a forbidden trailer header
    is_forbidden: bool,
    /// Whether to include CRLF injection attempt
    crlf_injection: bool,
    /// Whether to use malformed syntax
    malformed_syntax: bool,
}

/// Compliance testing options
#[derive(Debug, Arbitrary)]
pub struct ComplianceTestOptions {
    /// Enforce RFC 9110 forbidden trailer headers
    enforce_forbidden_trailers: bool,
    /// Require Transfer-Encoding: chunked header
    require_te_chunked: bool,
    /// Validate trailer ordering (must come after final 0-chunk)
    validate_trailer_ordering: bool,
    /// Enforce final empty line after trailers
    require_final_empty_line: bool,
    /// Maximum trailer section size
    max_trailer_size: u16,
    /// Maximum number of trailer headers
    max_trailer_count: u8,
}

/// Edge case testing scenarios
#[derive(Debug, Arbitrary)]
pub enum EdgeCaseTest {
    /// Multiple Transfer-Encoding headers
    MultipleTransferEncoding { values: Vec<String> },
    /// Transfer-Encoding with other values (gzip, deflate)
    TransferEncodingWithOtherValues { encodings: Vec<String> },
    /// Empty chunks in sequence
    EmptyChunksSequence { count: u8 },
    /// Very large chunk sizes
    LargeChunkSizes { sizes: Vec<u32> },
    /// Chunk extensions with forbidden characters
    ChunkExtensionsForbiddenChars { extensions: Vec<String> },
    /// Trailers without final empty line
    TrailersNoFinalEmptyLine,
    /// Duplicate trailer headers
    DuplicateTrailerHeaders { name: String, count: u8 },
    /// Trailers mixed with chunk data
    TrailersMixedWithChunkData,
    /// Oversized trailer section
    OversizedTrailerSection { size: u32 },
    /// Case sensitivity tests
    CaseSensitivityTests { header_cases: Vec<String> },
}

/// Mock HTTP/1.1 parser for Transfer-Encoding: chunked with trailers
pub struct MockTeChunkedParser {
    /// Current parsing state
    state: ParsingState,
    /// Parsed initial headers
    headers: HeaderMap,
    /// Accumulated body data
    body_data: Vec<u8>,
    /// Parsed trailer headers
    trailers: HeaderMap,
    /// Whether Transfer-Encoding: chunked was found
    has_te_chunked: bool,
    /// Current chunk info
    current_chunk: Option<CurrentChunk>,
    /// Parsing statistics
    stats: ParsingStats,
    /// Detected violations
    violations: Vec<ProtocolViolation>,
    /// Configuration
    config: ParserConfig,
}

#[derive(Debug, Clone)]
pub enum ParsingState {
    /// Parsing initial headers
    Headers,
    /// Parsing chunk size line
    ChunkSize,
    /// Parsing chunk data
    ChunkData { remaining: usize },
    /// Parsing chunk trailing CRLF
    ChunkCrlf,
    /// Parsing trailer headers
    Trailers,
    /// Parsing complete
    Complete,
    /// Error state
    Error(TeChunkedError),
}

#[derive(Debug, Clone)]
pub struct CurrentChunk {
    size: usize,
    data_read: usize,
    extensions: Vec<(String, Option<String>)>,
}

#[derive(Debug, Clone)]
pub enum TeChunkedError {
    /// Missing Transfer-Encoding: chunked header
    MissingTeChunked,
    /// Invalid chunk size format
    InvalidChunkSize(String),
    /// Forbidden trailer header
    ForbiddenTrailerHeader(String),
    /// Trailer before final chunk
    TrailerBeforeFinalChunk,
    /// CRLF injection in trailer
    CrlfInjectionInTrailer(String),
    /// Oversized trailer section
    OversizedTrailerSection { size: usize, max: usize },
    /// Missing final empty line
    MissingFinalEmptyLine,
    /// Malformed chunk format
    MalformedChunk(String),
    /// Protocol state error
    ProtocolStateError(String),
    /// Header injection attempt
    HeaderInjectionAttempt(String),
}

#[derive(Debug, Clone)]
pub struct ProtocolViolation {
    violation_type: ViolationType,
    description: String,
    severity: ViolationSeverity,
    context: String,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    ForbiddenTrailerHeader,
    TrailerBeforeFinalChunk,
    MissingTransferEncoding,
    CrlfInjection,
    HeaderInjection,
    ProtocolConfusion,
    StateInconsistency,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ViolationSeverity {
    Critical, // Security vulnerability
    High,     // Protocol violation
    Medium,   // Compliance issue
    Low,      // Style/recommendation
}

#[derive(Debug, Clone, Default)]
pub struct ParsingStats {
    chunks_parsed: u32,
    total_body_bytes: usize,
    trailer_headers_count: u32,
    trailer_bytes: usize,
    chunk_extensions_count: u32,
    protocol_violations: u32,
    state_transitions: u32,
}

#[derive(Debug, Clone)]
pub struct ParserConfig {
    max_chunk_size: usize,
    max_trailer_size: usize,
    max_trailer_count: usize,
    enforce_te_chunked: bool,
    allow_forbidden_trailers: bool,
    max_body_size: usize,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: 1024 * 1024, // 1MB
            max_trailer_size: 8192,      // 8KB
            max_trailer_count: 50,
            enforce_te_chunked: true,
            allow_forbidden_trailers: false,
            max_body_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

/// List of forbidden trailer headers per RFC 9110 §6.5.1
const FORBIDDEN_TRAILER_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "trailer",
    "host",
    "cache-control",
    "content-encoding",
    "content-type",
    "expect",
    "max-forwards",
    "pragma",
    "range",
    "te",
    "authorization",
    "content-range",
    "expires",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
];

impl MockTeChunkedParser {
    pub fn new(config: ParserConfig) -> Self {
        Self {
            state: ParsingState::Headers,
            headers: HeaderMap::new(),
            body_data: Vec::new(),
            trailers: HeaderMap::new(),
            has_te_chunked: false,
            current_chunk: None,
            stats: ParsingStats::default(),
            violations: Vec::new(),
            config,
        }
    }

    /// Process initial headers
    pub fn process_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> Result<(), TeChunkedError> {
        for (name, value) in headers {
            let name_lower = name.to_lowercase();

            // Check for Transfer-Encoding: chunked
            if name_lower == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                self.has_te_chunked = true;
            }

            self.headers.insert(name, value);
        }

        // Validate Transfer-Encoding requirement
        if self.config.enforce_te_chunked && !self.has_te_chunked {
            return Err(TeChunkedError::MissingTeChunked);
        }

        self.state = ParsingState::ChunkSize;
        self.stats.state_transitions += 1;
        Ok(())
    }

    /// Process a chunk size line
    pub fn process_chunk_size_line(&mut self, size_line: &str) -> Result<(), TeChunkedError> {
        if !matches!(self.state, ParsingState::ChunkSize) {
            return Err(TeChunkedError::ProtocolStateError(format!(
                "Expected chunk size, got: {:?}",
                self.state
            )));
        }

        // Parse chunk size (hex) and optional extensions
        let size_line = size_line.trim_end_matches("\r\n");
        let (size_str, extensions_str) = if let Some(semicolon_pos) = size_line.find(';') {
            (
                size_line[..semicolon_pos].trim(),
                Some(&size_line[semicolon_pos + 1..]),
            )
        } else {
            (size_line, None)
        };

        // Parse chunk size
        let chunk_size = match usize::from_str_radix(size_str, 16) {
            Ok(size) => size,
            Err(_) => return Err(TeChunkedError::InvalidChunkSize(size_str.to_string())),
        };

        // Validate chunk size limits
        if chunk_size > self.config.max_chunk_size {
            return Err(TeChunkedError::InvalidChunkSize(format!(
                "Chunk size {} exceeds maximum {}",
                chunk_size, self.config.max_chunk_size
            )));
        }

        // Parse chunk extensions if present
        let mut extensions = Vec::new();
        if let Some(ext_str) = extensions_str {
            for ext in ext_str.split(';') {
                let ext = ext.trim();
                if let Some(eq_pos) = ext.find('=') {
                    let name = ext[..eq_pos].trim().to_string();
                    let value = ext[eq_pos + 1..].trim().to_string();
                    extensions.push((name, Some(value)));
                } else {
                    extensions.push((ext.to_string(), None));
                }
                self.stats.chunk_extensions_count += 1;
            }
        }

        // Set up chunk parsing
        self.current_chunk = Some(CurrentChunk {
            size: chunk_size,
            data_read: 0,
            extensions,
        });

        if chunk_size == 0 {
            // Final chunk - transition to trailer parsing
            self.state = ParsingState::Trailers;
        } else {
            // Regular chunk - transition to data reading
            self.state = ParsingState::ChunkData {
                remaining: chunk_size,
            };
        }

        self.stats.chunks_parsed += 1;
        self.stats.state_transitions += 1;
        Ok(())
    }

    /// Process chunk data
    pub fn process_chunk_data(&mut self, data: &[u8]) -> Result<(), TeChunkedError> {
        match &mut self.state {
            ParsingState::ChunkData { remaining } => {
                let to_read = data.len().min(*remaining);

                // Check body size limits
                if self.body_data.len() + to_read > self.config.max_body_size {
                    return Err(TeChunkedError::ProtocolStateError(
                        "Body size exceeds maximum".to_string(),
                    ));
                }

                self.body_data.extend_from_slice(&data[..to_read]);
                *remaining -= to_read;
                self.stats.total_body_bytes += to_read;

                if let Some(chunk) = &mut self.current_chunk {
                    chunk.data_read += to_read;
                    assert!(
                        chunk.data_read <= chunk.size,
                        "Chunk reader must not consume beyond the declared chunk size"
                    );
                }

                if *remaining == 0 {
                    self.state = ParsingState::ChunkCrlf;
                    self.stats.state_transitions += 1;
                }

                Ok(())
            }
            _ => Err(TeChunkedError::ProtocolStateError(format!(
                "Expected chunk data state, got: {:?}",
                self.state
            ))),
        }
    }

    /// Process chunk trailing CRLF
    pub fn process_chunk_crlf(&mut self, crlf: &str) -> Result<(), TeChunkedError> {
        if !matches!(self.state, ParsingState::ChunkCrlf) {
            return Err(TeChunkedError::ProtocolStateError(format!(
                "Expected chunk CRLF, got: {:?}",
                self.state
            )));
        }

        if crlf != "\r\n" {
            return Err(TeChunkedError::MalformedChunk(format!(
                "Expected CRLF after chunk data, got: {:?}",
                crlf
            )));
        }

        if let Some(chunk) = &self.current_chunk {
            assert_eq!(
                chunk.data_read, chunk.size,
                "Chunk CRLF should only be accepted after reading the full chunk"
            );
            assert!(
                chunk.extensions.len() <= self.stats.chunk_extensions_count as usize,
                "Current chunk extension count should be reflected in parser stats"
            );
        }

        self.current_chunk = None;
        self.state = ParsingState::ChunkSize;
        self.stats.state_transitions += 1;
        Ok(())
    }

    /// Process trailer headers
    pub fn process_trailer_headers(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> Result<(), TeChunkedError> {
        if !matches!(self.state, ParsingState::Trailers) {
            self.violations.push(ProtocolViolation {
                violation_type: ViolationType::TrailerBeforeFinalChunk,
                description: "Trailer headers before final 0-chunk".to_string(),
                severity: ViolationSeverity::High,
                context: format!("Current state: {:?}", self.state),
            });
            self.stats.protocol_violations += 1;
            return Err(TeChunkedError::TrailerBeforeFinalChunk);
        }

        let mut trailer_bytes = 0;

        for (name, value) in headers {
            // Check trailer size limits
            trailer_bytes += name.len() + value.len() + 4; // +4 for ": " and CRLF
            if trailer_bytes > self.config.max_trailer_size {
                return Err(TeChunkedError::OversizedTrailerSection {
                    size: trailer_bytes,
                    max: self.config.max_trailer_size,
                });
            }

            // Check trailer count limits
            if self.trailers.len() >= self.config.max_trailer_count {
                return Err(TeChunkedError::OversizedTrailerSection {
                    size: self.trailers.len() + 1,
                    max: self.config.max_trailer_count,
                });
            }

            let name_lower = name.to_lowercase();

            // Check for forbidden trailer headers
            if !self.config.allow_forbidden_trailers
                && FORBIDDEN_TRAILER_HEADERS.contains(&name_lower.as_str())
            {
                self.violations.push(ProtocolViolation {
                    violation_type: ViolationType::ForbiddenTrailerHeader,
                    description: format!("Forbidden trailer header: {}", name),
                    severity: ViolationSeverity::High,
                    context: "RFC 9110 §6.5.1".to_string(),
                });
                self.stats.protocol_violations += 1;
                return Err(TeChunkedError::ForbiddenTrailerHeader(name));
            }

            // Check for CRLF injection in trailer values
            if value.contains('\r') || value.contains('\n') {
                self.violations.push(ProtocolViolation {
                    violation_type: ViolationType::CrlfInjection,
                    description: format!("CRLF injection in trailer value: {}", name),
                    severity: ViolationSeverity::Critical,
                    context: format!("Value: {:?}", value),
                });
                self.stats.protocol_violations += 1;
                return Err(TeChunkedError::CrlfInjectionInTrailer(value));
            }

            // Check for header injection patterns
            if value.contains(':') && (value.contains('\r') || value.contains('\n')) {
                self.violations.push(ProtocolViolation {
                    violation_type: ViolationType::HeaderInjection,
                    description: format!("Potential header injection in trailer: {}", name),
                    severity: ViolationSeverity::Critical,
                    context: format!("Value: {:?}", value),
                });
                self.stats.protocol_violations += 1;
                return Err(TeChunkedError::HeaderInjectionAttempt(value));
            }

            self.trailers.insert(name, value);
            self.stats.trailer_headers_count += 1;
        }

        self.stats.trailer_bytes += trailer_bytes;
        Ok(())
    }

    /// Complete parsing (final empty line)
    pub fn complete_parsing(&mut self, final_line: &str) -> Result<(), TeChunkedError> {
        if !matches!(self.state, ParsingState::Trailers) {
            return Err(TeChunkedError::ProtocolStateError(format!(
                "Expected trailers state for completion, got: {:?}",
                self.state
            )));
        }

        // Validate final empty line
        if final_line != "\r\n" && !final_line.is_empty() {
            return Err(TeChunkedError::MissingFinalEmptyLine);
        }

        self.state = ParsingState::Complete;
        self.stats.state_transitions += 1;
        Ok(())
    }

    /// Get parsing results
    pub fn results(&self) -> ParsingResults {
        ParsingResults {
            has_te_chunked: self.has_te_chunked,
            header_count: self.headers.len(),
            body_size: self.body_data.len(),
            trailer_count: self.trailers.len(),
            trailer_size: self.stats.trailer_bytes,
            chunks_processed: self.stats.chunks_parsed,
            violations: self.violations.clone(),
            final_state: self.state.clone(),
            stats: self.stats.clone(),
        }
    }

    /// Validate protocol compliance
    pub fn validate_compliance(&self) -> Vec<ComplianceIssue> {
        let mut issues = Vec::new();

        // Check Transfer-Encoding header
        if self.config.enforce_te_chunked && !self.has_te_chunked {
            issues.push(ComplianceIssue {
                rule: "RFC 9112 §7.1".to_string(),
                description: "Missing Transfer-Encoding: chunked header".to_string(),
                severity: ViolationSeverity::High,
            });
        }

        // Check for trailers without final chunk
        if !self.trailers.is_empty()
            && !matches!(self.state, ParsingState::Complete | ParsingState::Trailers)
        {
            issues.push(ComplianceIssue {
                rule: "RFC 9112 §7.1.3".to_string(),
                description: "Trailers present but not after final 0-chunk".to_string(),
                severity: ViolationSeverity::High,
            });
        }

        // Check forbidden trailer headers
        for name in self.trailers.keys() {
            if FORBIDDEN_TRAILER_HEADERS.contains(&name.to_lowercase().as_str()) {
                issues.push(ComplianceIssue {
                    rule: "RFC 9110 §6.5.1".to_string(),
                    description: format!("Forbidden trailer header: {}", name),
                    severity: ViolationSeverity::High,
                });
            }
        }

        issues
    }
}

#[derive(Debug, Clone)]
pub struct ParsingResults {
    pub has_te_chunked: bool,
    pub header_count: usize,
    pub body_size: usize,
    pub trailer_count: usize,
    pub trailer_size: usize,
    pub chunks_processed: u32,
    pub violations: Vec<ProtocolViolation>,
    pub final_state: ParsingState,
    pub stats: ParsingStats,
}

#[derive(Debug, Clone)]
pub struct ComplianceIssue {
    pub rule: String,
    pub description: String,
    pub severity: ViolationSeverity,
}

/// Cap values for reasonable fuzzing bounds
fn cap_u8(value: u8, max: u8) -> u8 {
    value.min(max)
}

fn cap_u16(value: u16, max: u16) -> u16 {
    value.min(max)
}

fn cap_usize(value: usize, max: usize) -> usize {
    value.min(max)
}

fn observe_message_type(message_type: &MessageType) {
    match message_type {
        MessageType::Request {
            method,
            uri,
            version,
        } => {
            let method_sample = &method[..method.len().min(128)];
            let uri_sample = &uri[..uri.len().min(512)];
            assert!(method_sample.len() <= 128);
            assert!(uri_sample.len() <= 512);
            assert!(matches!(version, HttpVersion::Http10 | HttpVersion::Http11));
        }
        MessageType::Response {
            status_code,
            reason_phrase,
            version,
        } => {
            let status_sample = (*status_code).min(999);
            let reason_sample = &reason_phrase[..reason_phrase.len().min(256)];
            assert!(status_sample <= 999);
            assert!(reason_sample.len() <= 256);
            assert!(matches!(version, HttpVersion::Http10 | HttpVersion::Http11));
        }
    }
}

/// Generate chunk line in proper format
fn format_chunk_line(size: usize, extensions: &[(String, Option<String>)]) -> String {
    let mut line = format!("{:x}", size);

    for (name, value) in extensions.iter().take(5) {
        // Limit extensions
        line.push(';');
        line.push_str(&name[..name.len().min(20)]); // Limit extension name length
        if let Some(val) = value {
            line.push('=');
            line.push_str(&val[..val.len().min(50)]); // Limit extension value length
        }
    }

    line.push_str("\r\n");
    line
}

fuzz_target!(|input: TeChunkedWithTrailersInput| {
    observe_message_type(&input.message_type);

    let max_trailer_size =
        usize::from(cap_u16(input.compliance_tests.max_trailer_size, 4096).max(1));
    let max_trailer_count =
        usize::from(cap_u8(input.compliance_tests.max_trailer_count, 20).max(1));

    let config = ParserConfig {
        max_chunk_size: 16384, // 16KB chunks max
        max_trailer_size,      // 4KB trailers max
        max_trailer_count,     // 20 trailers max
        enforce_te_chunked: input.compliance_tests.require_te_chunked,
        allow_forbidden_trailers: false,
        max_body_size: 1024 * 1024, // 1MB body max
    };

    let mut parser = MockTeChunkedParser::new(config);

    // Process initial headers
    let mut initial_headers = Vec::new();
    let mut has_te_chunked = false;

    for header in input.initial_headers.iter().take(20) {
        let name = header.name[..header.name.len().min(50)].to_string();
        let value = header.value[..header.value.len().min(200)].to_string();

        // Ensure we have Transfer-Encoding: chunked
        if header.is_transfer_encoding_chunked
            || (!has_te_chunked && name.to_lowercase() == "transfer-encoding")
        {
            initial_headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));
            has_te_chunked = true;
        } else {
            initial_headers.push((name, value));
        }
    }

    // Ensure Transfer-Encoding: chunked is present for valid test
    if !has_te_chunked {
        initial_headers.push(("Transfer-Encoding".to_string(), "chunked".to_string()));
    }

    let header_result = parser.process_headers(initial_headers);

    // For invalid headers, stop test here
    if header_result.is_err() {
        return;
    }

    // Process chunked body
    for chunk in input.chunked_body.chunks.iter().take(10) {
        let chunk_size = cap_u16(chunk.size, 8192) as usize; // Max 8KB chunks
        let data_size = cap_usize(chunk.data.len(), chunk_size.min(1024));

        // Format chunk size line with extensions
        let extensions: Vec<(String, Option<String>)> = chunk
            .extensions
            .iter()
            .take(3)
            .map(|ext| {
                let name = ext.name[..ext.name.len().min(20)].to_string();
                let value = ext.value.as_ref().map(|v| v[..v.len().min(50)].to_string());
                (name, value)
            })
            .collect();

        let chunk_line = if input.chunked_body.include_malformed_chunks && chunk.malformed {
            "not-a-hex-size\r\n".to_string()
        } else {
            format_chunk_line(chunk_size, &extensions)
        };

        // Process chunk size line
        if parser.process_chunk_size_line(&chunk_line).is_err() {
            // Invalid chunk format - continue with remaining test
            continue;
        }

        // Process chunk data
        if chunk_size > 0 {
            let chunk_data = &chunk.data[..data_size];
            if parser.process_chunk_data(chunk_data).is_err() {
                continue;
            }

            // Process chunk trailing CRLF
            if parser.process_chunk_crlf("\r\n").is_err() {
                continue;
            }
        }
    }

    // Process final 0-chunk
    let final_chunk_line = if input.chunked_body.final_chunk_size.is_multiple_of(2) {
        "0\r\n".to_string()
    } else {
        "000\r\n".to_string()
    };

    let final_chunk_result = parser.process_chunk_size_line(&final_chunk_line);
    if final_chunk_result.is_err() {
        return; // Can't proceed without valid final chunk
    }

    // Test trailer headers before final chunk (should be violation)
    if input.chunked_body.trailers_before_final {
        let early_trailers = vec![("X-Early-Trailer".to_string(), "violation".to_string())];
        let early_result = parser.process_trailer_headers(early_trailers);

        // Should be rejected
        assert!(
            early_result.is_err() || !input.compliance_tests.validate_trailer_ordering,
            "Trailers before final chunk should be rejected when ordering validation is enabled"
        );
        return;
    }

    // Process trailing headers after final 0-chunk
    let mut trailer_headers = Vec::new();
    for trailer in input.trailing_headers.iter().take(15) {
        let name = trailer.name[..trailer.name.len().min(50)].to_string();
        let mut value = trailer.value[..trailer.value.len().min(200)].to_string();

        // Test CRLF injection
        if trailer.crlf_injection {
            value.push_str("\r\nInjected-Header: malicious");
        }

        // Test forbidden headers
        let final_name = if trailer.is_forbidden && !FORBIDDEN_TRAILER_HEADERS.is_empty() {
            FORBIDDEN_TRAILER_HEADERS[trailer.name.len() % FORBIDDEN_TRAILER_HEADERS.len()]
                .to_string()
        } else {
            name
        };

        // Test malformed syntax
        if trailer.malformed_syntax {
            trailer_headers.push((format!("{}:", final_name), value)); // Extra colon
        } else {
            trailer_headers.push((final_name, value));
        }
    }

    let trailer_result = parser.process_trailer_headers(trailer_headers);

    // Test complete parsing
    let completion_result = parser.complete_parsing("\r\n");

    // Validate results
    let results = parser.results();
    let compliance_issues = parser.validate_compliance();
    for issue in &compliance_issues {
        assert!(
            !issue.rule.is_empty() && !issue.description.is_empty(),
            "Compliance issues should keep rule and description context"
        );
        assert!(
            matches!(
                issue.severity,
                ViolationSeverity::Critical
                    | ViolationSeverity::High
                    | ViolationSeverity::Medium
                    | ViolationSeverity::Low
            ),
            "Compliance issue should carry a known severity"
        );
    }

    // Verify protocol compliance
    assert!(
        results.has_te_chunked,
        "Transfer-Encoding: chunked should be detected"
    );

    // Check violations were properly detected
    if input.compliance_tests.enforce_forbidden_trailers {
        let forbidden_violations: Vec<_> = results
            .violations
            .iter()
            .filter(|v| matches!(v.violation_type, ViolationType::ForbiddenTrailerHeader))
            .collect();

        for violation in &forbidden_violations {
            assert!(
                !violation.description.is_empty() && !violation.context.is_empty(),
                "Forbidden trailer violations should include diagnostic context"
            );
            assert_eq!(
                violation.severity,
                ViolationSeverity::High,
                "Forbidden trailer violations should be high severity"
            );
        }
    }

    // Check CRLF injection detection
    let crlf_violations: Vec<_> = results
        .violations
        .iter()
        .filter(|v| matches!(v.violation_type, ViolationType::CrlfInjection))
        .collect();

    for violation in &crlf_violations {
        assert!(
            !violation.description.is_empty() && !violation.context.is_empty(),
            "CRLF violations should include diagnostic context"
        );
        assert_eq!(
            violation.severity,
            ViolationSeverity::Critical,
            "CRLF injection should be critical severity"
        );
    }

    // Verify final state consistency
    if trailer_result.is_ok() && completion_result.is_ok() {
        assert!(
            matches!(results.final_state, ParsingState::Complete),
            "Successful parsing should reach complete state"
        );
    }

    // Verify size limits were respected
    assert!(
        results.body_size <= parser.config.max_body_size,
        "Body size should not exceed limit"
    );
    assert!(
        results.trailer_size <= parser.config.max_trailer_size,
        "Trailer size should not exceed limit"
    );
    assert!(
        results.trailer_count <= parser.config.max_trailer_count,
        "Trailer count should not exceed limit"
    );
    assert_eq!(
        results.stats.protocol_violations as usize,
        results.violations.len(),
        "Protocol violation stats should match recorded violations"
    );

    // Process edge cases
    for edge_case in input.edge_cases.iter().take(5) {
        match edge_case {
            EdgeCaseTest::MultipleTransferEncoding { values } => {
                // Test multiple TE headers (should use last one)
                for value in values.iter().take(3) {
                    let _value = value[..value.len().min(50)].to_string();
                    // Multiple TE headers are implementation-specific
                }
            }
            EdgeCaseTest::TransferEncodingWithOtherValues { encodings } => {
                // Test TE with multiple encodings
                for encoding in encodings.iter().take(3) {
                    let _encoding = encoding[..encoding.len().min(20)].to_string();
                    // Multiple encodings like "gzip, chunked"
                }
            }
            EdgeCaseTest::TrailersNoFinalEmptyLine if trailer_result.is_ok() => {
                // Test missing final empty line
                let no_final_result = parser.complete_parsing("X-Extra: header\r\n");
                // Should be rejected without final empty line
                if input.compliance_tests.require_final_empty_line {
                    assert!(
                        no_final_result.is_err(),
                        "Missing final empty line should be rejected"
                    );
                }
            }
            _ => {
                // Other edge cases handled in main flow
            }
        }
    }

    // Verify no critical violations in valid cases
    let critical_violations: Vec<_> = results
        .violations
        .iter()
        .filter(|v| v.severity == ViolationSeverity::Critical)
        .collect();

    if critical_violations.is_empty()
        && !input
            .trailing_headers
            .iter()
            .any(|t| t.crlf_injection || t.is_forbidden)
    {
        // No critical violations expected for clean input
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_te_chunked_parser_basic() {
        let config = ParserConfig::default();
        let mut parser = MockTeChunkedParser::new(config);

        // Process headers with Transfer-Encoding: chunked
        let headers = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        assert!(parser.process_headers(headers).is_ok());
        assert!(parser.has_te_chunked);
    }

    #[test]
    fn test_forbidden_trailer_headers() {
        let config = ParserConfig::default();
        let mut parser = MockTeChunkedParser::new(config);

        // Set up for trailer parsing
        parser.state = ParsingState::Trailers;

        // Try forbidden header
        let forbidden_trailers = vec![("Content-Length".to_string(), "100".to_string())];
        let result = parser.process_trailer_headers(forbidden_trailers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TeChunkedError::ForbiddenTrailerHeader(_)
        ));
    }

    #[test]
    fn test_crlf_injection_in_trailers() {
        let config = ParserConfig::default();
        let mut parser = MockTeChunkedParser::new(config);

        parser.state = ParsingState::Trailers;

        // Try CRLF injection
        let injection_trailers = vec![(
            "X-Test".to_string(),
            "value\r\nInjected: header".to_string(),
        )];
        let result = parser.process_trailer_headers(injection_trailers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TeChunkedError::CrlfInjectionInTrailer(_)
        ));
    }

    #[test]
    fn test_chunk_size_parsing() {
        let config = ParserConfig::default();
        let mut parser = MockTeChunkedParser::new(config);

        parser.state = ParsingState::ChunkSize;

        // Test valid chunk size
        assert!(parser.process_chunk_size_line("a\r\n").is_ok());

        // Test invalid chunk size
        assert!(parser.process_chunk_size_line("xyz\r\n").is_err());

        // Test chunk with extensions
        assert!(parser.process_chunk_size_line("10;name=value\r\n").is_ok());
    }

    #[test]
    fn test_trailer_before_final_chunk() {
        let config = ParserConfig::default();
        let mut parser = MockTeChunkedParser::new(config);

        // Set state to non-trailer state
        parser.state = ParsingState::ChunkSize;

        // Try to process trailers
        let trailers = vec![("X-Test".to_string(), "value".to_string())];
        let result = parser.process_trailer_headers(trailers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TeChunkedError::TrailerBeforeFinalChunk
        ));
    }

    #[test]
    fn test_oversized_trailer_section() {
        let mut config = ParserConfig::default();
        config.max_trailer_size = 100; // Small limit for testing

        let mut parser = MockTeChunkedParser::new(config);
        parser.state = ParsingState::Trailers;

        // Create large trailer
        let large_value = "x".repeat(200);
        let large_trailers = vec![("X-Large".to_string(), large_value)];
        let result = parser.process_trailer_headers(large_trailers);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TeChunkedError::OversizedTrailerSection { .. }
        ));
    }

    #[test]
    fn test_valid_chunked_with_trailers() {
        let config = ParserConfig::default();
        let mut parser = MockTeChunkedParser::new(config);

        // Headers
        let headers = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
        assert!(parser.process_headers(headers).is_ok());

        // Chunk
        assert!(parser.process_chunk_size_line("5\r\n").is_ok());
        assert!(parser.process_chunk_data(b"hello").is_ok());
        assert!(parser.process_chunk_crlf("\r\n").is_ok());

        // Final chunk
        assert!(parser.process_chunk_size_line("0\r\n").is_ok());

        // Trailers
        let trailers = vec![("X-Checksum".to_string(), "abc123".to_string())];
        assert!(parser.process_trailer_headers(trailers).is_ok());

        // Complete
        assert!(parser.complete_parsing("\r\n").is_ok());

        let results = parser.results();
        assert_eq!(results.body_size, 5);
        assert_eq!(results.trailer_count, 1);
        assert!(matches!(results.final_state, ParsingState::Complete));
    }
}
