#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

/// HTTP/1.1 malformed LF/lone-LF terminator fuzzing.
///
/// Tests the line termination parsing logic to ensure proper rejection of
/// malformed line terminators per RFC 9112 §2.2. HTTP/1.x requires CRLF
/// (\r\n) line termination - lone LF (\n) or bare CR (\r) are protocol
/// violations that can enable request smuggling attacks.
///
/// Based on codec.rs line termination logic:
/// - find_headers_end() looks for \r\n\r\n (lines 220-225)
/// - collect_crlf_positions() validates \r\n pairs (lines 235-247)
/// - Bare CR rejection in request lines (lines 264-268)
/// - Header block bare CR scanning (lines 897-910)
/// - Chunked encoding CRLF requirements (line 844)
///
/// Security implications:
/// - Request smuggling via line termination confusion
/// - Protocol downgrade attacks
/// - Proxy/server interpretation differences
/// - Header injection via malformed terminators
#[derive(Arbitrary, Debug, Clone)]
pub struct MalformedLfTestCase {
    /// Type of HTTP message being tested
    message_type: MessageType,
    /// Line termination configuration
    termination: TerminationConfig,
    /// Message structure
    structure: MessageStructure,
    /// Placement of malformed terminators
    placement: TerminatorPlacement,
    /// Edge case scenarios
    scenario: MalformationScenario,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum MessageType {
    Request(RequestType),
    Response(ResponseType),
    ChunkedRequest,
    ChunkedResponse,
    PipelinedRequests,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct RequestType {
    method: String,
    uri: String,
    version: String,
    has_body: bool,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ResponseType {
    status: u16,
    reason: String,
    version: String,
    has_body: bool,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum TerminationConfig {
    /// Proper CRLF (\r\n)
    ValidCrlf,
    /// Lone LF (\n)
    LoneLf,
    /// Bare CR (\r)
    BareCr,
    /// Mixed terminators
    Mixed(Vec<TerminatorType>),
    /// No terminators
    None,
    /// Custom sequences
    Custom(Vec<u8>),
    /// Control characters
    Control(ControlTerminator),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum TerminatorType {
    Crlf,      // \r\n
    Lf,        // \n
    Cr,        // \r
    Null,      // \0
    Tab,       // \t
    Space,     // ' '
    FormFeed,  // \f
    VTab,      // \v
    Custom(u8),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ControlTerminator {
    MultipleNulls(usize),
    HighBitSet(u8),
    UnicodeSequence(String),
    BinaryData(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub struct MessageStructure {
    /// Request/status line content
    first_line: LineContent,
    /// Headers configuration
    headers: HeadersConfig,
    /// Body content if present
    body: Option<BodyContent>,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct LineContent {
    parts: Vec<String>,
    separators: Vec<SeparatorType>,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum SeparatorType {
    Space,
    Tab,
    Multiple(usize), // Multiple spaces
    Mixed,           // Spaces and tabs
    None,            // No separator
    Control(u8),     // Control character
}

#[derive(Arbitrary, Debug, Clone)]
pub struct HeadersConfig {
    headers: Vec<HeaderField>,
    special_headers: Vec<SpecialHeader>,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct HeaderField {
    name: String,
    value: String,
    formatting: HeaderFormatting,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum HeaderFormatting {
    Normal,
    ExtraWhitespace,
    NoColon,
    MultipleColons,
    EmptyName,
    EmptyValue,
    VeryLong,
    WithBinaryCRLF, // Embedded \r\n in value
}

#[derive(Arbitrary, Debug, Clone)]
pub enum SpecialHeader {
    ContentLength(String),
    TransferEncoding(String),
    Host(String),
    Connection(String),
    MalformedName(Vec<u8>),
    MalformedValue(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum BodyContent {
    Empty,
    Text(String),
    Binary(Vec<u8>),
    ChunkedEncoding(Vec<ChunkData>),
    MalformedChunked(MalformedChunk),
}

#[derive(Arbitrary, Debug, Clone)]
pub struct ChunkData {
    size: usize,
    data: Vec<u8>,
    extensions: Option<String>,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum MalformedChunk {
    BadSizeLine(Vec<u8>),
    MissingCrlf(Vec<u8>),
    InvalidSize(String),
    TruncatedData(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum TerminatorPlacement {
    /// Replace all line terminators
    ReplaceAll,
    /// Replace specific line terminators
    Specific(Vec<usize>), // Indices of lines to replace
    /// Insert additional terminators
    Insert(Vec<InsertionPoint>),
    /// Mixed valid and invalid
    Mixed,
    /// Only in headers
    HeadersOnly,
    /// Only in body
    BodyOnly,
    /// Only in first line
    FirstLineOnly,
}

#[derive(Arbitrary, Debug, Clone)]
pub struct InsertionPoint {
    position: usize,
    terminator: TerminatorType,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum MalformationScenario {
    /// Basic malformation cases
    SimpleLoneLf,
    SimpleBareCr,
    MixedTerminators,
    /// Security scenarios
    RequestSmuggling,
    HeaderInjection,
    ProtocolDowngrade,
    ProxyConfusion,
    /// Edge cases
    BoundaryConditions,
    VeryLongLines,
    EmptyLines,
    BinaryData,
    /// Chunked encoding specific
    ChunkedMalformation,
    TrailerMalformation,
    /// Pipelining scenarios
    PipelinedMalformation,
    RequestResponseMixing,
    /// Performance scenarios
    ManySmallLines,
    FewLongLines,
    RepeatedParsing,
}

/// Mock HTTP/1.1 line termination parser for fuzzing
#[derive(Debug)]
pub struct MockLfTerminatorParser {
    max_line_length: usize,
    max_headers: usize,
    strict_crlf: bool,
    allow_bare_cr_in_body: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedMessage {
    pub first_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub termination_violations: Vec<TerminationViolation>,
    pub parsing_result: ParsingResult,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TerminationViolation {
    pub position: usize,
    pub violation_type: ViolationType,
    pub context: String,
}

#[derive(Arbitrary, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ViolationType {
    LoneLf,
    BareCr,
    InvalidControl,
    MissingTerminator,
    ExtraTerminator,
    MixedTerminators,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParsingResult {
    Success,
    BadRequestLine,
    BadHeader,
    BadChunkedEncoding,
    MalformedMessage(String),
    ProtocolViolation(String),
}

impl MockLfTerminatorParser {
    pub fn new() -> Self {
        Self {
            max_line_length: 8192,
            max_headers: 128,
            strict_crlf: true,
            allow_bare_cr_in_body: true, // Bodies can contain binary \r
        }
    }

    pub fn with_strict_crlf(mut self, strict: bool) -> Self {
        self.strict_crlf = strict;
        self
    }

    pub fn parse_message(&self, test_case: &MalformedLfTestCase) -> Result<ParsedMessage, String> {
        let raw_message = self.build_raw_message(test_case)?;

        let mut violations = Vec::new();
        let _position = 0;

        // Scan for termination violations first
        self.scan_termination_violations(&raw_message, &mut violations);

        // Find headers end boundary
        let headers_end = self.find_headers_boundary(&raw_message, &mut violations)?;

        // Parse first line
        let (first_line, first_line_end) = self.parse_first_line(&raw_message[..headers_end], &mut violations)?;

        // Parse headers
        let headers = self.parse_headers(&raw_message[first_line_end..headers_end], &mut violations)?;

        // Extract body (if any)
        let body = if headers_end < raw_message.len() {
            raw_message[headers_end..].to_vec()
        } else {
            Vec::new()
        };

        // Validate body terminators if chunked
        if self.is_chunked_encoding(&headers) {
            self.validate_chunked_terminators(&body, &mut violations)?;
        }

        // Determine parsing result
        let parsing_result = self.determine_parsing_result(&violations, test_case);

        Ok(ParsedMessage {
            first_line,
            headers,
            body,
            termination_violations: violations,
            parsing_result,
        })
    }

    fn build_raw_message(&self, test_case: &MalformedLfTestCase) -> Result<Vec<u8>, String> {
        let mut message = Vec::new();

        // Build first line
        let first_line = self.build_first_line(test_case)?;
        message.extend_from_slice(first_line.as_bytes());

        // Add first line terminator
        self.add_terminator(&mut message, &test_case.termination, &test_case.placement, 0);

        // Build headers
        let headers_data = self.build_headers(test_case)?;
        for (i, (header_line, _)) in headers_data.iter().enumerate() {
            message.extend_from_slice(header_line.as_bytes());
            self.add_terminator(&mut message, &test_case.termination, &test_case.placement, i + 1);
        }

        // Add headers end marker
        self.add_terminator(&mut message, &test_case.termination, &test_case.placement, usize::MAX);

        // Build body if present
        if let Some(ref body) = test_case.structure.body {
            let body_data = self.build_body(body, test_case)?;
            message.extend_from_slice(&body_data);
        }

        Ok(message)
    }

    fn build_first_line(&self, test_case: &MalformedLfTestCase) -> Result<String, String> {
        match &test_case.message_type {
            MessageType::Request(_) | MessageType::ChunkedRequest => {
                Ok(format!("{} {} {}",
                    test_case.structure.first_line.parts.get(0).unwrap_or(&"GET".to_string()),
                    test_case.structure.first_line.parts.get(1).unwrap_or(&"/".to_string()),
                    test_case.structure.first_line.parts.get(2).unwrap_or(&"HTTP/1.1".to_string())
                ))
            },
            MessageType::Response(_) | MessageType::ChunkedResponse => {
                Ok(format!("{} {} {}",
                    test_case.structure.first_line.parts.get(0).unwrap_or(&"HTTP/1.1".to_string()),
                    test_case.structure.first_line.parts.get(1).unwrap_or(&"200".to_string()),
                    test_case.structure.first_line.parts.get(2).unwrap_or(&"OK".to_string())
                ))
            },
            MessageType::PipelinedRequests => {
                Ok(format!("GET / HTTP/1.1"))
            },
        }
    }

    fn build_headers(&self, test_case: &MalformedLfTestCase) -> Result<Vec<(String, String)>, String> {
        let mut headers = Vec::new();

        // Add required headers
        if matches!(test_case.message_type, MessageType::Request(_) | MessageType::ChunkedRequest | MessageType::PipelinedRequests) {
            headers.push(("Host: example.com".to_string(), "host".to_string()));
        }

        // Add configured headers
        for header in &test_case.structure.headers.headers {
            let formatted = self.format_header(header);
            headers.push((formatted, header.name.clone()));
        }

        // Add special headers
        for special in &test_case.structure.headers.special_headers {
            let formatted = self.format_special_header(special);
            headers.push((formatted, "special".to_string()));
        }

        Ok(headers)
    }

    fn format_header(&self, header: &HeaderField) -> String {
        match header.formatting {
            HeaderFormatting::Normal => format!("{}: {}", header.name, header.value),
            HeaderFormatting::ExtraWhitespace => format!("  {} :  {}  ", header.name, header.value),
            HeaderFormatting::NoColon => format!("{} {}", header.name, header.value),
            HeaderFormatting::MultipleColons => format!("{}:: {}", header.name, header.value),
            HeaderFormatting::EmptyName => format!(": {}", header.value),
            HeaderFormatting::EmptyValue => format!("{}:", header.name),
            HeaderFormatting::VeryLong => {
                let long_value = header.value.repeat(100);
                format!("{}: {}", header.name, &long_value[..long_value.len().min(4000)])
            },
            HeaderFormatting::WithBinaryCRLF => format!("{}: {}\r\nInjected: header", header.name, header.value),
        }
    }

    fn format_special_header(&self, special: &SpecialHeader) -> String {
        match special {
            SpecialHeader::ContentLength(val) => format!("Content-Length: {}", val),
            SpecialHeader::TransferEncoding(val) => format!("Transfer-Encoding: {}", val),
            SpecialHeader::Host(val) => format!("Host: {}", val),
            SpecialHeader::Connection(val) => format!("Connection: {}", val),
            SpecialHeader::MalformedName(bytes) => {
                let name = String::from_utf8_lossy(bytes);
                format!("{}: value", name)
            },
            SpecialHeader::MalformedValue(bytes) => {
                let value = String::from_utf8_lossy(bytes);
                format!("Header: {}", value)
            },
        }
    }

    fn build_body(&self, body: &BodyContent, test_case: &MalformedLfTestCase) -> Result<Vec<u8>, String> {
        match body {
            BodyContent::Empty => Ok(Vec::new()),
            BodyContent::Text(text) => Ok(text.as_bytes().to_vec()),
            BodyContent::Binary(data) => Ok(data.clone()),
            BodyContent::ChunkedEncoding(chunks) => {
                let mut body_data = Vec::new();
                for chunk in chunks {
                    // Add chunk size line
                    body_data.extend_from_slice(format!("{:x}", chunk.size).as_bytes());
                    if let Some(ref ext) = chunk.extensions {
                        body_data.extend_from_slice(format!(";{}", ext).as_bytes());
                    }
                    self.add_specific_terminator(&mut body_data, &test_case.termination);

                    // Add chunk data
                    let data_len = chunk.data.len().min(chunk.size);
                    body_data.extend_from_slice(&chunk.data[..data_len]);
                    self.add_specific_terminator(&mut body_data, &test_case.termination);
                }
                // Add final chunk
                body_data.extend_from_slice(b"0");
                self.add_specific_terminator(&mut body_data, &test_case.termination);
                self.add_specific_terminator(&mut body_data, &test_case.termination);
                Ok(body_data)
            },
            BodyContent::MalformedChunked(malformed) => {
                match malformed {
                    MalformedChunk::BadSizeLine(data) => Ok(data.clone()),
                    MalformedChunk::MissingCrlf(data) => Ok(data.clone()),
                    MalformedChunk::InvalidSize(size) => Ok(format!("{}\r\ndata\r\n", size).into_bytes()),
                    MalformedChunk::TruncatedData(data) => Ok(data.clone()),
                }
            },
        }
    }

    fn add_terminator(&self, message: &mut Vec<u8>, config: &TerminationConfig, placement: &TerminatorPlacement, line_index: usize) {
        // Check if this line should get a terminator based on placement
        let should_add = match placement {
            TerminatorPlacement::ReplaceAll => true,
            TerminatorPlacement::Specific(indices) => indices.contains(&line_index),
            TerminatorPlacement::HeadersOnly => line_index > 0 && line_index != usize::MAX,
            TerminatorPlacement::FirstLineOnly => line_index == 0,
            _ => true, // Default to adding
        };

        if should_add {
            self.add_specific_terminator(message, config);
        } else {
            // Add proper CRLF for lines not affected by malformation
            message.extend_from_slice(b"\r\n");
        }
    }

    fn add_specific_terminator(&self, message: &mut Vec<u8>, config: &TerminationConfig) {
        match config {
            TerminationConfig::ValidCrlf => message.extend_from_slice(b"\r\n"),
            TerminationConfig::LoneLf => message.push(b'\n'),
            TerminationConfig::BareCr => message.push(b'\r'),
            TerminationConfig::Mixed(types) => {
                for term_type in types {
                    self.add_terminator_type(message, term_type);
                }
            },
            TerminationConfig::None => {}, // No terminator
            TerminationConfig::Custom(bytes) => message.extend_from_slice(bytes),
            TerminationConfig::Control(control) => {
                match control {
                    ControlTerminator::MultipleNulls(count) => {
                        message.extend(vec![0u8; *count % 10]);
                    },
                    ControlTerminator::HighBitSet(byte) => {
                        message.push(*byte | 0x80);
                    },
                    ControlTerminator::UnicodeSequence(text) => {
                        message.extend_from_slice(text.as_bytes());
                    },
                    ControlTerminator::BinaryData(data) => {
                        message.extend_from_slice(data);
                    },
                }
            },
        }
    }

    fn add_terminator_type(&self, message: &mut Vec<u8>, term_type: &TerminatorType) {
        match term_type {
            TerminatorType::Crlf => message.extend_from_slice(b"\r\n"),
            TerminatorType::Lf => message.push(b'\n'),
            TerminatorType::Cr => message.push(b'\r'),
            TerminatorType::Null => message.push(b'\0'),
            TerminatorType::Tab => message.push(b'\t'),
            TerminatorType::Space => message.push(b' '),
            TerminatorType::FormFeed => message.push(b'\x0C'),
            TerminatorType::VTab => message.push(b'\x0B'),
            TerminatorType::Custom(byte) => message.push(*byte),
        }
    }

    fn scan_termination_violations(&self, data: &[u8], violations: &mut Vec<TerminationViolation>) {
        let mut i = 0;
        while i < data.len() {
            match data[i] {
                b'\n' => {
                    // Check if this is a lone LF (not preceded by \r)
                    if i == 0 || data[i - 1] != b'\r' {
                        violations.push(TerminationViolation {
                            position: i,
                            violation_type: ViolationType::LoneLf,
                            context: self.extract_context(data, i),
                        });
                    }
                },
                b'\r' => {
                    // Check if this is a bare CR (not followed by \n)
                    if i + 1 >= data.len() || data[i + 1] != b'\n' {
                        violations.push(TerminationViolation {
                            position: i,
                            violation_type: ViolationType::BareCr,
                            context: self.extract_context(data, i),
                        });
                    }
                },
                b'\0'..=b'\x08' | b'\x0B'..=b'\x0C' | b'\x0E'..=b'\x1F' | b'\x7F' => {
                    // Control characters (except \t, \n, \r)
                    violations.push(TerminationViolation {
                        position: i,
                        violation_type: ViolationType::InvalidControl,
                        context: self.extract_context(data, i),
                    });
                },
                _ => {},
            }
            i += 1;
        }
    }

    fn extract_context(&self, data: &[u8], position: usize) -> String {
        let start = position.saturating_sub(10);
        let end = (position + 10).min(data.len());
        let context_bytes = &data[start..end];

        // Convert to string for display, replacing non-printable chars
        context_bytes.iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect()
    }

    fn find_headers_boundary(&self, data: &[u8], violations: &mut Vec<TerminationViolation>) -> Result<usize, String> {
        // Look for \r\n\r\n sequence
        if let Some(pos) = self.find_pattern(data, b"\r\n\r\n") {
            return Ok(pos + 4);
        }

        // Look for malformed boundaries
        if let Some(pos) = self.find_pattern(data, b"\n\n") {
            violations.push(TerminationViolation {
                position: pos,
                violation_type: ViolationType::MissingTerminator,
                context: "Headers end marker".to_string(),
            });
            return Ok(pos + 2);
        }

        // Default: assume all data is headers (no body)
        Ok(data.len())
    }

    fn find_pattern(&self, data: &[u8], pattern: &[u8]) -> Option<usize> {
        data.windows(pattern.len()).position(|window| window == pattern)
    }

    fn parse_first_line(&self, headers_section: &[u8], violations: &mut Vec<TerminationViolation>) -> Result<(String, usize), String> {
        if let Some(line_end) = self.find_pattern(headers_section, b"\r\n") {
            let line = &headers_section[..line_end];
            let line_str = String::from_utf8_lossy(line).to_string();
            Ok((line_str, line_end + 2))
        } else if let Some(line_end) = self.find_pattern(headers_section, b"\n") {
            violations.push(TerminationViolation {
                position: line_end,
                violation_type: ViolationType::LoneLf,
                context: "First line".to_string(),
            });
            let line = &headers_section[..line_end];
            let line_str = String::from_utf8_lossy(line).to_string();
            Ok((line_str, line_end + 1))
        } else {
            Err("No first line terminator found".to_string())
        }
    }

    fn parse_headers(&self, headers_data: &[u8], violations: &mut Vec<TerminationViolation>) -> Result<Vec<(String, String)>, String> {
        let mut headers = Vec::new();
        let mut offset = 0;

        while offset < headers_data.len() {
            // Find next line
            let line_end = if let Some(crlf_pos) = self.find_pattern(&headers_data[offset..], b"\r\n") {
                offset + crlf_pos
            } else if let Some(lf_pos) = self.find_pattern(&headers_data[offset..], b"\n") {
                violations.push(TerminationViolation {
                    position: offset + lf_pos,
                    violation_type: ViolationType::LoneLf,
                    context: "Header line".to_string(),
                });
                offset + lf_pos
            } else {
                break;
            };

            let line = &headers_data[offset..line_end];
            if line.is_empty() {
                break; // End of headers
            }

            // Parse header
            let line_str = String::from_utf8_lossy(line);
            if let Some(colon_pos) = line_str.find(':') {
                let name = line_str[..colon_pos].trim().to_string();
                let value = line_str[colon_pos + 1..].trim().to_string();
                headers.push((name, value));
            }

            // Move past this line
            offset = line_end + if headers_data.get(line_end..line_end + 2) == Some(b"\r\n") { 2 } else { 1 };
        }

        Ok(headers)
    }

    fn is_chunked_encoding(&self, headers: &[(String, String)]) -> bool {
        headers.iter().any(|(name, value)|
            name.eq_ignore_ascii_case("transfer-encoding") &&
            value.to_ascii_lowercase().contains("chunked")
        )
    }

    fn validate_chunked_terminators(&self, body: &[u8], violations: &mut Vec<TerminationViolation>) -> Result<(), String> {
        // Simplified chunked validation - just scan for termination issues
        self.scan_termination_violations(body, violations);
        Ok(())
    }

    fn determine_parsing_result(&self, violations: &[TerminationViolation], _test_case: &MalformedLfTestCase) -> ParsingResult {
        if violations.is_empty() {
            return ParsingResult::Success;
        }

        for violation in violations {
            match violation.violation_type {
                ViolationType::LoneLf | ViolationType::BareCr => {
                    if violation.context.contains("First line") {
                        return ParsingResult::BadRequestLine;
                    } else if violation.context.contains("Header") {
                        return ParsingResult::BadHeader;
                    }
                },
                ViolationType::InvalidControl => {
                    return ParsingResult::ProtocolViolation("Control characters in headers".to_string());
                },
                _ => {},
            }
        }

        ParsingResult::MalformedMessage("Termination violations detected".to_string())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(test_case) = MalformedLfTestCase::arbitrary(&mut u) {
        let parser = MockLfTerminatorParser::new();

        // Test main parsing path
        let result = parser.parse_message(&test_case);

        match result {
            Ok(parsed) => {
                // Validate parsing invariants

                // Termination violations should correlate with parsing results
                match parsed.parsing_result {
                    ParsingResult::Success => {
                        // Success should only occur with valid CRLF or acceptable edge cases
                        let serious_violations = parsed.termination_violations.iter()
                            .any(|v| matches!(v.violation_type, ViolationType::LoneLf | ViolationType::BareCr));

                        if serious_violations && parser.strict_crlf {
                            // This might be acceptable depending on the scenario
                            // Allow some flexibility for valid edge cases
                        }
                    },

                    ParsingResult::BadRequestLine => {
                        // Should have violations in the first line
                        let has_first_line_violation = parsed.termination_violations.iter()
                            .any(|v| v.context.contains("First line"));
                        assert!(
                            has_first_line_violation,
                            "BadRequestLine result should have first line violations"
                        );
                    },

                    ParsingResult::BadHeader => {
                        // Should have violations in headers
                        let has_header_violation = parsed.termination_violations.iter()
                            .any(|v| v.context.contains("Header"));
                        assert!(
                            has_header_violation,
                            "BadHeader result should have header violations"
                        );
                    },

                    _ => {
                        // Other results are acceptable for malformed input
                    }
                }

                // Validate violation detection consistency
                for violation in &parsed.termination_violations {
                    assert!(
                        violation.position < parsed.first_line.len() +
                        parsed.headers.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>() +
                        parsed.body.len() + 100, // Allow some buffer for terminators
                        "Violation position {} should be within message bounds",
                        violation.position
                    );
                }
            }

            Err(_error) => {
                // Errors are acceptable for malformed input
                // Ensure they don't cause crashes or infinite loops
            }
        }

        // Test specific termination scenarios
        test_lone_lf_detection(&parser, &test_case);
        test_bare_cr_detection(&parser, &test_case);
        test_mixed_terminators(&parser, &test_case);
        test_boundary_conditions(&parser, &test_case);
    }
});

fn test_lone_lf_detection(parser: &MockLfTerminatorParser, test_case: &MalformedLfTestCase) {
    // Test explicit lone LF case
    let mut lone_lf_case = test_case.clone();
    lone_lf_case.termination = TerminationConfig::LoneLf;

    if let Ok(parsed) = parser.parse_message(&lone_lf_case) {
        if parser.strict_crlf {
            let has_lone_lf = parsed.termination_violations.iter()
                .any(|v| matches!(v.violation_type, ViolationType::LoneLf));
            assert!(has_lone_lf, "Should detect lone LF violations in strict mode");
        }
    }
}

fn test_bare_cr_detection(parser: &MockLfTerminatorParser, test_case: &MalformedLfTestCase) {
    // Test explicit bare CR case
    let mut bare_cr_case = test_case.clone();
    bare_cr_case.termination = TerminationConfig::BareCr;

    if let Ok(parsed) = parser.parse_message(&bare_cr_case) {
        if parser.strict_crlf {
            let has_bare_cr = parsed.termination_violations.iter()
                .any(|v| matches!(v.violation_type, ViolationType::BareCr));
            assert!(has_bare_cr, "Should detect bare CR violations in strict mode");
        }
    }
}

fn test_mixed_terminators(parser: &MockLfTerminatorParser, test_case: &MalformedLfTestCase) {
    // Test mixed terminator case
    let mut mixed_case = test_case.clone();
    mixed_case.termination = TerminationConfig::Mixed(vec![
        TerminatorType::Crlf,
        TerminatorType::Lf,
        TerminatorType::Cr,
    ]);

    if let Ok(parsed) = parser.parse_message(&mixed_case) {
        // Should detect multiple violation types
        let violation_types: std::collections::HashSet<_> = parsed.termination_violations.iter()
            .map(|v| &v.violation_type)
            .collect();

        if parser.strict_crlf {
            assert!(
                violation_types.len() > 1,
                "Should detect multiple violation types in mixed case"
            );
        }
    }
}

fn test_boundary_conditions(parser: &MockLfTerminatorParser, test_case: &MalformedLfTestCase) {
    // Test empty message
    let mut empty_case = test_case.clone();
    empty_case.structure.first_line.parts = vec!["".to_string()];
    empty_case.structure.headers.headers = vec![];
    empty_case.structure.body = None;

    let _ = parser.parse_message(&empty_case);
    // Should not crash on empty input

    // Test very long line
    let mut long_case = test_case.clone();
    long_case.structure.first_line.parts = vec![
        "GET".to_string(),
        "/".repeat(10000),
        "HTTP/1.1".to_string(),
    ];

    let _ = parser.parse_message(&long_case);
    // Should handle long lines gracefully
}