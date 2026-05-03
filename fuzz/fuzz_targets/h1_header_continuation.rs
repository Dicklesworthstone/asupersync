#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 header continuation (line-folding) fuzz target.
///
/// Tests RFC 9112 compliance for obsolete line-folding where headers continue
/// on the next line starting with whitespace (space or tab). Per RFC 9112 §5.2:
/// "A server that receives an obs-fold in a request message that is not within
/// a message/http container MUST either reject the message by sending a 400
/// (Bad Request), preferably with a representation explaining that obsolete
/// line folding is unacceptable."
///
/// Critical security issue: Line-folding is a header smuggling vector that
/// allows attackers to inject headers or manipulate header parsing between
/// different HTTP implementations.
///
/// Test cases:
/// - Headers with space continuation: "Header: value\r\n value2"
/// - Headers with tab continuation: "Header: value\r\n\tvalue2"
/// - Multiple continuation lines
/// - Mixed whitespace in continuation
/// - Continuation in security-critical headers (Authorization, Host, etc.)

#[derive(Arbitrary, Debug, Clone)]
struct HeaderContinuationInput {
    /// Base header name
    header_name: String,

    /// Base header value
    header_value: String,

    /// Continuation patterns to test
    continuation: ContinuationPattern,

    /// HTTP method and path
    request_line: RequestLine,

    /// Additional headers for context
    additional_headers: Vec<HeaderPair>,

    /// Validation policy configuration
    policy: ContinuationPolicy,
}

#[derive(Arbitrary, Debug, Clone)]
struct RequestLine {
    method: String,
    path: String,
    version: String,
}

impl Default for RequestLine {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            path: "/".to_string(),
            version: "HTTP/1.1".to_string(),
        }
    }
}

#[derive(Arbitrary, Debug, Clone)]
struct HeaderPair {
    name: String,
    value: String,
}

#[derive(Arbitrary, Debug, Clone)]
struct ContinuationPattern {
    /// Type of continuation whitespace
    whitespace_type: WhitespaceType,

    /// Number of continuation lines
    continuation_count: u8,

    /// Whether to use mixed whitespace
    mixed_whitespace: bool,

    /// Position of continuation (start, middle, end of value)
    continuation_position: ContinuationPosition,

    /// Whether to include security-critical headers
    security_critical: bool,
}

#[derive(Arbitrary, Debug, Clone, PartialEq)]
enum WhitespaceType {
    Space,
    Tab,
    Multiple,
    Mixed,
}

#[derive(Arbitrary, Debug, Clone)]
enum ContinuationPosition {
    StartOfValue,
    MiddleOfValue,
    EndOfValue,
    MultiplePositions,
}

#[derive(Arbitrary, Debug, Clone)]
struct ContinuationPolicy {
    /// Whether to enforce strict RFC 9112 compliance
    strict_rfc9112: bool,

    /// Whether to allow any line-folding at all
    allow_line_folding: bool,

    /// Maximum header line length
    max_header_length: usize,

    /// Whether to reject on first continuation or parse all
    fail_fast: bool,
}

impl Default for ContinuationPolicy {
    fn default() -> Self {
        Self {
            strict_rfc9112: true,
            allow_line_folding: false,
            max_header_length: 8192,
            fail_fast: true,
        }
    }
}

/// Mock HTTP/1.1 header parser for testing continuation rejection
struct MockH1HeaderParser {
    policy: ContinuationPolicy,
}

impl MockH1HeaderParser {
    fn new(policy: ContinuationPolicy) -> Self {
        Self { policy }
    }

    /// Parse HTTP/1.1 request and validate header continuation per RFC 9112 §5.2
    fn parse_request(&self, input: &HeaderContinuationInput) -> HeaderParseResult {
        let raw_request = self.build_raw_request(input);

        // Check for line-folding patterns
        if let Some(violation) = self.detect_line_folding(&raw_request) {
            if self.policy.strict_rfc9112 && !self.policy.allow_line_folding {
                return HeaderParseResult::BadRequest(format!(
                    "RFC 9112 §5.2 violation: {}",
                    violation
                ));
            }
        }

        // Parse headers line by line
        self.parse_headers_strict(&raw_request)
    }

    fn build_raw_request(&self, input: &HeaderContinuationInput) -> String {
        let mut request = format!(
            "{} {} {}\r\n",
            input.request_line.method, input.request_line.path, input.request_line.version
        );

        // Add main header with continuation
        let header_with_continuation = self.build_continuation_header(
            &input.header_name,
            &input.header_value,
            &input.continuation,
        );
        request.push_str(&header_with_continuation);

        // Add additional headers
        for header in &input.additional_headers {
            request.push_str(&format!("{}: {}\r\n", header.name, header.value));
        }

        request.push_str("\r\n"); // End of headers
        request
    }

    fn build_continuation_header(
        &self,
        name: &str,
        value: &str,
        pattern: &ContinuationPattern,
    ) -> String {
        let mut header = format!("{}: {}", name, value);

        for i in 0..pattern.continuation_count.min(5) {
            // Limit for performance
            let whitespace = match pattern.whitespace_type {
                WhitespaceType::Space => " ".to_string(),
                WhitespaceType::Tab => "\t".to_string(),
                WhitespaceType::Multiple => "  ".to_string(),
                WhitespaceType::Mixed => if i % 2 == 0 { " " } else { "\t" }.to_string(),
            };

            let continuation_value = match pattern.continuation_position {
                ContinuationPosition::StartOfValue => "continued-start",
                ContinuationPosition::MiddleOfValue => "continued-middle",
                ContinuationPosition::EndOfValue => "continued-end",
                ContinuationPosition::MultiplePositions => &format!("continued-{}", i),
            };

            header.push_str(&format!("\r\n{}{}", whitespace, continuation_value));
        }

        header.push_str("\r\n");
        header
    }

    fn detect_line_folding(&self, request: &str) -> Option<String> {
        let lines: Vec<&str> = request.split("\r\n").collect();

        for (i, line) in lines.iter().enumerate().skip(1) {
            // Skip request line
            if line.is_empty() {
                break; // End of headers
            }

            // RFC 9112 §5.2: obs-fold = CRLF 1*( SP / HTAB )
            if line.starts_with(' ') || line.starts_with('\t') {
                return Some(format!(
                    "Line {} starts with whitespace (obs-fold): {:?}",
                    i + 1,
                    line.chars().take(10).collect::<String>()
                ));
            }

            // Additional whitespace patterns
            if line.starts_with("  ") || line.starts_with("\t\t") {
                return Some(format!(
                    "Line {} starts with multiple whitespace characters: {:?}",
                    i + 1,
                    line.chars().take(10).collect::<String>()
                ));
            }
        }

        None
    }

    fn parse_headers_strict(&self, request: &str) -> HeaderParseResult {
        let lines: Vec<&str> = request.split("\r\n").collect();
        let mut headers = Vec::new();
        let mut current_header: Option<(String, String)> = None;

        for (line_num, line) in lines.iter().enumerate().skip(1) {
            // Skip request line
            if line.is_empty() {
                break; // End of headers
            }

            // Check header line length
            if line.len() > self.policy.max_header_length {
                return HeaderParseResult::BadRequest(format!(
                    "Header line {} exceeds maximum length",
                    line_num + 1
                ));
            }

            // Detect continuation (forbidden)
            if line.starts_with(' ') || line.starts_with('\t') {
                return self.handle_continuation_line(line, line_num + 1, &current_header);
            }

            // Complete previous header if any
            if let Some((name, value)) = current_header.take() {
                headers.push((name, value));
            }

            // Parse new header
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_string();
                let value = line[colon_pos + 1..].trim().to_string();

                // Validate header name
                if let Err(msg) = self.validate_header_name(&name) {
                    return HeaderParseResult::BadRequest(msg);
                }

                current_header = Some((name, value));
            } else {
                return HeaderParseResult::BadRequest(format!(
                    "Malformed header line {}: missing colon",
                    line_num + 1
                ));
            }
        }

        // Complete final header
        if let Some((name, value)) = current_header {
            headers.push((name, value));
        }

        // Additional security validation
        self.validate_security_headers(&headers)
    }

    fn handle_continuation_line(
        &self,
        line: &str,
        line_num: usize,
        current_header: &Option<(String, String)>,
    ) -> HeaderParseResult {
        if self.policy.strict_rfc9112 {
            // RFC 9112 §5.2: MUST reject with 400 Bad Request
            return HeaderParseResult::BadRequest(format!(
                "RFC 9112 §5.2: Obsolete line folding at line {}: {:?}",
                line_num,
                line.chars().take(20).collect::<String>()
            ));
        }

        if self.policy.allow_line_folding {
            // Legacy behavior: fold the line
            if let Some((name, mut value)) = current_header.clone() {
                value.push(' ');
                value.push_str(line.trim());
                return HeaderParseResult::Valid(vec![(name, value)]);
            }
        }

        HeaderParseResult::BadRequest(format!("Unexpected continuation line {}", line_num))
    }

    fn validate_header_name(&self, name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("Empty header name".to_string());
        }

        // RFC 9112 header name validation (token chars only)
        for ch in name.chars() {
            if !ch.is_ascii() || ch.is_control() || ch.is_whitespace() {
                return Err(format!("Invalid character in header name: {:?}", ch));
            }
            if matches!(
                ch,
                '(' | ')'
                    | '<'
                    | '>'
                    | '@'
                    | ','
                    | ';'
                    | ':'
                    | '\\'
                    | '"'
                    | '/'
                    | '['
                    | ']'
                    | '?'
                    | '='
                    | '{'
                    | '}'
            ) {
                return Err(format!("Forbidden character in header name: {:?}", ch));
            }
        }

        Ok(())
    }

    fn validate_security_headers(&self, headers: &[(String, String)]) -> HeaderParseResult {
        let mut security_critical = Vec::new();

        for (name, value) in headers {
            let name_lower = name.to_lowercase();

            // Check for security-critical headers that could be smuggled
            if matches!(
                name_lower.as_str(),
                "authorization"
                    | "host"
                    | "content-length"
                    | "transfer-encoding"
                    | "x-forwarded-for"
                    | "x-real-ip"
                    | "x-forwarded-host"
                    | "proxy-authorization"
                    | "cookie"
                    | "set-cookie"
            ) {
                security_critical.push((name.clone(), value.clone()));

                // Additional validation for critical headers
                if name_lower == "content-length" && value.contains(' ') {
                    return HeaderParseResult::SecurityViolation(
                        "Content-Length header contains whitespace (potential smuggling)"
                            .to_string(),
                    );
                }

                if name_lower == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                    if !value.trim().to_lowercase().ends_with("chunked") {
                        return HeaderParseResult::SecurityViolation(
                            "Transfer-Encoding chunked not at end (potential smuggling)"
                                .to_string(),
                        );
                    }
                }
            }
        }

        if security_critical.is_empty() {
            HeaderParseResult::Valid(headers.to_vec())
        } else {
            HeaderParseResult::ValidWithSecurityHeaders {
                headers: headers.to_vec(),
                security_headers: security_critical,
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum HeaderParseResult {
    /// Headers parsed successfully
    Valid(Vec<(String, String)>),

    /// Headers valid but contain security-critical headers
    ValidWithSecurityHeaders {
        headers: Vec<(String, String)>,
        security_headers: Vec<(String, String)>,
    },

    /// RFC 9112 violation, must return 400 Bad Request
    BadRequest(String),

    /// Security violation detected (potential header smuggling)
    SecurityViolation(String),
}

fuzz_target!(|input: HeaderContinuationInput| {
    // Normalize input for reasonable fuzzing bounds
    let mut input = input;
    if input.header_name.is_empty() {
        input.header_name = "X-Test".to_string();
    }
    if input.header_value.is_empty() {
        input.header_value = "value".to_string();
    }

    // Limit continuation count for performance
    input.continuation.continuation_count = input.continuation.continuation_count.min(3);

    let parser = MockH1HeaderParser::new(input.policy.clone());
    let result = parser.parse_request(&input);

    // Test RFC 9112 §5.2 compliance
    match result {
        HeaderParseResult::BadRequest(ref msg) => {
            // Line-folding should be rejected with specific RFC violation
            if input.continuation.continuation_count > 0 {
                assert!(
                    msg.contains("RFC 9112")
                        || msg.contains("obs-fold")
                        || msg.contains("obsolete")
                        || msg.contains("line folding"),
                    "Line-folding rejection should mention RFC 9112: {}",
                    msg
                );
            }

            // Whitespace continuation should be flagged
            if matches!(
                input.continuation.whitespace_type,
                WhitespaceType::Space | WhitespaceType::Tab | WhitespaceType::Multiple
            ) {
                assert!(
                    msg.contains("whitespace")
                        || msg.contains("continuation")
                        || msg.contains("starts with"),
                    "Whitespace continuation not properly flagged: {}",
                    msg
                );
            }
        }

        HeaderParseResult::SecurityViolation(ref msg) => {
            // Security violations should mention smuggling or specific attack vector
            assert!(
                msg.contains("smuggling")
                    || msg.contains("potential")
                    || msg.contains("Transfer-Encoding")
                    || msg.contains("Content-Length"),
                "Security violation should explain attack vector: {}",
                msg
            );
        }

        HeaderParseResult::Valid(_) | HeaderParseResult::ValidWithSecurityHeaders { .. } => {
            // Valid parsing should only occur when line-folding is allowed or not present
            if input.continuation.continuation_count > 0
                && input.policy.strict_rfc9112
                && !input.policy.allow_line_folding
            {
                panic!("Line-folding should be rejected under strict RFC 9112 policy");
            }
        }
    }

    // Additional security checks for critical headers
    if input.continuation.security_critical {
        let security_header_names = [
            "authorization",
            "host",
            "content-length",
            "transfer-encoding",
        ];
        if security_header_names
            .iter()
            .any(|&name| input.header_name.to_lowercase().contains(name))
        {
            match result {
                HeaderParseResult::BadRequest(_) | HeaderParseResult::SecurityViolation(_) => {
                    // Expected for security-critical headers with line-folding
                }
                HeaderParseResult::ValidWithSecurityHeaders { .. } => {
                    // Acceptable if properly flagged
                }
                HeaderParseResult::Valid(_) => {
                    if input.continuation.continuation_count > 0 {
                        panic!("Security-critical headers with line-folding should be flagged");
                    }
                }
            }
        }
    }

    // Consistency checks
    if input.policy.fail_fast && input.continuation.continuation_count > 0 {
        match result {
            HeaderParseResult::BadRequest(_) => {
                // Expected under fail-fast policy
            }
            _ => {
                if input.policy.strict_rfc9112 && !input.policy.allow_line_folding {
                    panic!("Fail-fast policy should reject line-folding immediately");
                }
            }
        }
    }

    // Whitespace type validation
    match input.continuation.whitespace_type {
        WhitespaceType::Space | WhitespaceType::Tab
            if input.continuation.continuation_count > 0 =>
        {
            if input.policy.strict_rfc9112 && !input.policy.allow_line_folding {
                match result {
                    HeaderParseResult::BadRequest(_) => {
                        // Expected - RFC compliant rejection
                    }
                    _ => panic!("Space/tab continuation should be rejected under RFC 9112"),
                }
            }
        }
        _ => {}
    }
});
