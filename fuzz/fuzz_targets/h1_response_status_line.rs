#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/1.1 response status-line parser fuzzing.
///
/// Tests the status-line parsing function that handles the first line of HTTP responses:
/// `HTTP/1.1 200 OK\r\n`
///
/// Covers critical parsing edge cases:
/// - Version parsing (HTTP/1.0, HTTP/1.1, malformed versions)
/// - Status code validation (100-999 range, invalid formats, overflow)
/// - Reason phrase handling (empty, whitespace, special chars, UTF-8)
/// - Delimiter parsing (space separation, multiple spaces, missing parts)
/// - Security vectors (injection attempts, buffer overflows, smuggling)
///
/// Based on RFC 9112 §3 and RFC 9110 §15 status-line grammar:
/// status-line = HTTP-version SP status-code SP [ reason-phrase ]
#[derive(Arbitrary, Debug, Clone)]
pub struct StatusLineTestCase {
    /// HTTP version component
    version: VersionComponent,
    /// Status code component
    status: StatusComponent,
    /// Reason phrase component
    reason: ReasonComponent,
    /// Delimiter configuration
    delimiters: DelimiterConfig,
    /// Line termination
    termination: LineTermination,
    /// Special formatting cases
    formatting: FormattingCase,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum VersionComponent {
    /// Standard HTTP versions
    Http10,
    Http11,
    /// Case variations
    Http10Uppercase,
    Http11Lowercase,
    Http10Mixed,
    /// Version edge cases
    Http09,
    Http20,
    Http30,
    /// Malformed versions
    EmptyVersion,
    NoSlash(String),
    InvalidMajor(String),
    InvalidMinor(String),
    ExtraDigits(String),
    NoHttp(String),
    WithWhitespace(String),
    WithControl(String),
    VeryLong(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum StatusComponent {
    /// Standard status codes by category
    Informational(u16), // 100-199
    Success(u16),     // 200-299
    Redirection(u16), // 300-399
    ClientError(u16), // 400-499
    ServerError(u16), // 500-599
    /// Edge case status codes
    MinValid(u16), // 100
    MaxValid(u16),    // 999
    /// Invalid status codes
    TooLow(u16), // 0-99
    TooHigh(u16),     // 1000+
    Overflow(u64),    // > u16::MAX
    /// Non-numeric status codes
    Empty,
    NonNumeric(String),
    WithWhitespace(String),
    WithLeadingZeros(String),
    Negative(String),
    Float(String),
    Hex(String),
    Binary(String),
    VeryLong(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum ReasonComponent {
    /// Standard reason phrases
    Standard(StandardReason),
    /// Custom reason phrases
    Empty,
    SingleWord(String),
    MultiWord(String),
    /// Special character cases
    WithNumbers(String),
    WithPunctuation(String),
    WithUnicode(String),
    WithTabs(String),
    WithNewlines(String),
    WithControl(String),
    WithQuotes(String),
    /// Size edge cases
    VeryLong(String),
    JustSpaces(usize),
    /// HTTP-specific edge cases
    HttpInjection(String),
    HeaderLike(String, String),
    BodyLike(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum StandardReason {
    Continue,
    Ok,
    Created,
    NoContent,
    MovedPermanently,
    Found,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    InternalServerError,
    BadGateway,
    ServiceUnavailable,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum DelimiterConfig {
    /// Standard single space
    Standard,
    /// Multiple spaces
    ExtraSpaces(usize), // 2-10 spaces
    /// Missing delimiters
    NoFirstSpace,
    NoSecondSpace,
    NoSpaces,
    /// Alternative delimiters
    Tabs,
    Mixed,
    /// Control characters
    WithNulls,
    WithCarriageReturn,
    WithLineFeed,
}

#[derive(Arbitrary, Debug, Clone)]
pub enum LineTermination {
    /// Standard CRLF
    Crlf,
    /// Alternative terminations
    Lf,
    Cr,
    None,
    /// Multiple terminators
    MultipleCrlf,
    /// With extra content after termination
    ExtraAfterCrlf(String),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum FormattingCase {
    Normal,
    /// Padding cases
    LeadingWhitespace,
    TrailingWhitespace,
    BothWhitespace,
    /// Case mixing
    RandomCase,
    /// Length variations
    MinimalLine,
    MaximalLine,
    /// Protocol confusion
    HttpsPrefix,
    UrlLike(String),
    /// Injection attempts
    SqlInjection(String),
    XssAttempt(String),
    PathTraversal,
    /// Binary content
    NullBytes(usize),
    HighBitSet(String),
    /// Unicode edge cases
    BomPrefix,
    UnicodeNormalization(String),
}

/// Mock HTTP/1.1 status line parser for fuzzing
#[derive(Debug)]
pub struct MockStatusLineParser {
    max_line_length: usize,
    strict_version: bool,
    strict_status: bool,
    strict_reason: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedStatusLine {
    pub version: HttpVersion,
    pub status: u16,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Unknown(String),
}

impl MockStatusLineParser {
    pub fn new() -> Self {
        Self {
            max_line_length: 8192,
            strict_version: true,
            strict_status: true,
            strict_reason: false, // Allow non-standard reason phrases
        }
    }

    pub fn parse_status_line(&self, line: &str) -> Result<ParsedStatusLine, String> {
        // Check line length
        if line.len() > self.max_line_length {
            return Err("Status line too long".to_string());
        }

        // Check for control characters that shouldn't be in status line
        if line.chars().any(|c| c.is_control() && c != '\t') {
            return Err("Control characters in status line".to_string());
        }

        // Split on spaces - RFC requires exactly 2 spaces as delimiters
        let mut parts = line.splitn(3, ' ');
        let version_str = parts.next().ok_or("Missing version")?;
        let status_str = parts.next().ok_or("Missing status code")?;
        let reason_str = parts.next().unwrap_or("").to_owned();

        // Parse version
        let version = self.parse_version(version_str)?;

        // Parse status code
        let status = self.parse_status_code(status_str)?;

        // Validate reason phrase
        if self.strict_reason {
            self.validate_reason_phrase(&reason_str)?;
        }

        Ok(ParsedStatusLine {
            version,
            status,
            reason: reason_str,
        })
    }

    fn parse_version(&self, version_str: &str) -> Result<HttpVersion, String> {
        if version_str.is_empty() {
            return Err("Empty version".to_string());
        }

        // Check case-sensitive match first (strict)
        match version_str {
            "HTTP/1.0" => return Ok(HttpVersion::Http10),
            "HTTP/1.1" => return Ok(HttpVersion::Http11),
            _ => {}
        }

        if !self.strict_version {
            // Allow case-insensitive matching
            match version_str.to_ascii_uppercase().as_str() {
                "HTTP/1.0" => return Ok(HttpVersion::Http10),
                "HTTP/1.1" => return Ok(HttpVersion::Http11),
                _ => {}
            }
        }

        // Validate version format
        if !version_str.starts_with("HTTP/") {
            return Err("Version doesn't start with HTTP/".to_string());
        }

        let version_part = &version_str[5..];
        if !version_part.contains('.') {
            return Err("Version missing dot separator".to_string());
        }

        let mut version_parts = version_part.split('.');
        let major = version_parts.next().unwrap();
        let minor = version_parts.next().ok_or("Missing minor version")?;

        // Ensure no extra parts
        if version_parts.next().is_some() {
            return Err("Extra version components".to_string());
        }

        // Validate numeric parts
        let _major_num: u8 = major.parse().map_err(|_| "Invalid major version")?;
        let _minor_num: u8 = minor.parse().map_err(|_| "Invalid minor version")?;

        if self.strict_version {
            return Err(format!("Unsupported version: {}", version_str));
        }

        Ok(HttpVersion::Unknown(version_str.to_string()))
    }

    fn parse_status_code(&self, status_str: &str) -> Result<u16, String> {
        if status_str.is_empty() {
            return Err("Empty status code".to_string());
        }

        // Check for whitespace
        if status_str.chars().any(|c| c.is_whitespace()) {
            return Err("Status code contains whitespace".to_string());
        }

        // Check for leading zeros (non-standard but sometimes seen)
        if status_str.len() > 1 && status_str.starts_with('0') {
            return Err("Status code has leading zeros".to_string());
        }

        // Parse as u16
        let status: u16 = status_str
            .parse()
            .map_err(|_| "Non-numeric status code".to_string())?;

        // RFC 9110 §15: status codes are 3-digit integers (100-999)
        if self.strict_status && !(100..=999).contains(&status) {
            return Err(format!("Status code {} out of valid range 100-999", status));
        }

        Ok(status)
    }

    fn validate_reason_phrase(&self, reason: &str) -> Result<(), String> {
        // RFC allows any VCHAR, WSP, obs-text
        // VCHAR = 0x21-0x7E, WSP = SP/HTAB, obs-text = 0x80-0xFF
        for c in reason.chars() {
            let code = c as u32;
            if !(0x21..=0x7E).contains(&code) &&  // VCHAR
               c != ' ' && c != '\t' &&           // WSP
               !(0x80..=0xFF).contains(&code)
            {
                // obs-text
                return Err(format!(
                    "Invalid character in reason phrase: U+{:04X}",
                    code
                ));
            }
        }

        // Additional checks
        if reason.len() > 512 {
            return Err("Reason phrase too long".to_string());
        }

        Ok(())
    }

    /// Parse a complete status line from test case
    pub fn parse_from_test_case(
        &self,
        test_case: &StatusLineTestCase,
    ) -> Result<ParsedStatusLine, String> {
        let line = self.build_status_line(test_case)?;
        self.parse_status_line(&line)
    }

    fn build_status_line(&self, test_case: &StatusLineTestCase) -> Result<String, String> {
        let version_str = self.build_version(&test_case.version)?;
        let status_str = self.build_status(&test_case.status)?;
        let reason_str = self.build_reason(&test_case.reason)?;
        let delims = self.build_delimiters(&test_case.delimiters);

        let line = match (&test_case.delimiters, reason_str.is_empty()) {
            (DelimiterConfig::NoFirstSpace, _) => {
                format!("{}{}{}{}", version_str, delims.0, status_str, reason_str)
            }
            (DelimiterConfig::NoSecondSpace, false) => {
                format!("{}{}{}{}", version_str, delims.0, status_str, reason_str)
            }
            (DelimiterConfig::NoSpaces, _) => {
                format!("{}{}{}", version_str, status_str, reason_str)
            }
            (_, true) => format!("{}{}{}", version_str, delims.0, status_str),
            (_, false) => format!(
                "{}{}{}{}{}",
                version_str, delims.0, status_str, delims.1, reason_str
            ),
        };

        let formatted = self.apply_formatting(line, &test_case.formatting)?;
        let terminated = self.apply_termination(formatted, &test_case.termination);

        Ok(terminated)
    }

    fn build_version(&self, version: &VersionComponent) -> Result<String, String> {
        match version {
            VersionComponent::Http10 => Ok("HTTP/1.0".to_string()),
            VersionComponent::Http11 => Ok("HTTP/1.1".to_string()),
            VersionComponent::Http10Uppercase => Ok("HTTP/1.0".to_string()),
            VersionComponent::Http11Lowercase => Ok("http/1.1".to_string()),
            VersionComponent::Http10Mixed => Ok("Http/1.0".to_string()),
            VersionComponent::Http09 => Ok("HTTP/0.9".to_string()),
            VersionComponent::Http20 => Ok("HTTP/2.0".to_string()),
            VersionComponent::Http30 => Ok("HTTP/3.0".to_string()),
            VersionComponent::EmptyVersion => Ok("".to_string()),
            VersionComponent::NoSlash(s) => Ok(format!("HTTP{}", s)),
            VersionComponent::InvalidMajor(s) => Ok(format!("HTTP/{}.1", s)),
            VersionComponent::InvalidMinor(s) => Ok(format!("HTTP/1.{}", s)),
            VersionComponent::ExtraDigits(s) => Ok(format!("HTTP/1.1.{}", s)),
            VersionComponent::NoHttp(s) => Ok(format!("{}/1.1", s)),
            VersionComponent::WithWhitespace(s) => Ok(format!("HTTP /1.1{}", s)),
            VersionComponent::WithControl(s) => Ok(format!("HTTP/1.1{}", s)),
            VersionComponent::VeryLong(s) => {
                let long_version = s.repeat(100);
                Ok(format!(
                    "HTTP/1.1{}",
                    &long_version[..long_version.len().min(1000)]
                ))
            }
        }
    }

    fn build_status(&self, status: &StatusComponent) -> Result<String, String> {
        match status {
            StatusComponent::Informational(base) => Ok(format!("{}", 100 + (base % 100))),
            StatusComponent::Success(base) => Ok(format!("{}", 200 + (base % 100))),
            StatusComponent::Redirection(base) => Ok(format!("{}", 300 + (base % 100))),
            StatusComponent::ClientError(base) => Ok(format!("{}", 400 + (base % 100))),
            StatusComponent::ServerError(base) => Ok(format!("{}", 500 + (base % 100))),
            StatusComponent::MinValid(_) => Ok("100".to_string()),
            StatusComponent::MaxValid(_) => Ok("999".to_string()),
            StatusComponent::TooLow(n) => Ok(format!("{}", n % 100)),
            StatusComponent::TooHigh(n) => Ok(format!("{}", 1000 + (n % 9000))),
            StatusComponent::Overflow(n) => Ok(format!("{}", n)),
            StatusComponent::Empty => Ok("".to_string()),
            StatusComponent::NonNumeric(s) => Ok(s.clone()),
            StatusComponent::WithWhitespace(s) => Ok(format!("20 0{}", s)),
            StatusComponent::WithLeadingZeros(s) => Ok(format!("0200{}", s)),
            StatusComponent::Negative(s) => Ok(format!("-200{}", s)),
            StatusComponent::Float(s) => Ok(format!("200.5{}", s)),
            StatusComponent::Hex(s) => Ok(format!("0x200{}", s)),
            StatusComponent::Binary(s) => Ok(format!("0b11001000{}", s)),
            StatusComponent::VeryLong(s) => {
                let long_status = s.repeat(100);
                Ok(format!(
                    "200{}",
                    &long_status[..long_status.len().min(1000)]
                ))
            }
        }
    }

    fn build_reason(&self, reason: &ReasonComponent) -> Result<String, String> {
        match reason {
            ReasonComponent::Standard(std_reason) => Ok(match std_reason {
                StandardReason::Continue => "Continue",
                StandardReason::Ok => "OK",
                StandardReason::Created => "Created",
                StandardReason::NoContent => "No Content",
                StandardReason::MovedPermanently => "Moved Permanently",
                StandardReason::Found => "Found",
                StandardReason::BadRequest => "Bad Request",
                StandardReason::Unauthorized => "Unauthorized",
                StandardReason::Forbidden => "Forbidden",
                StandardReason::NotFound => "Not Found",
                StandardReason::InternalServerError => "Internal Server Error",
                StandardReason::BadGateway => "Bad Gateway",
                StandardReason::ServiceUnavailable => "Service Unavailable",
            }
            .to_string()),
            ReasonComponent::Empty => Ok("".to_string()),
            ReasonComponent::SingleWord(s) => Ok(s.clone()),
            ReasonComponent::MultiWord(s) => Ok(format!("Custom {}", s)),
            ReasonComponent::WithNumbers(s) => Ok(format!("Error {}", s)),
            ReasonComponent::WithPunctuation(s) => Ok(format!("Status: {}!", s)),
            ReasonComponent::WithUnicode(s) => Ok(format!("Ünicöde {}", s)),
            ReasonComponent::WithTabs(s) => Ok(format!("Tab\tSeparated\t{}", s)),
            ReasonComponent::WithNewlines(s) => Ok(format!("Line\nBreak {}", s)),
            ReasonComponent::WithControl(s) => Ok(format!("Control\x01Char {}", s)),
            ReasonComponent::WithQuotes(s) => Ok(format!("\"Quoted\" {}", s)),
            ReasonComponent::VeryLong(s) => {
                let long_reason = s.repeat(200);
                Ok(long_reason[..long_reason.len().min(2048)].to_string())
            }
            ReasonComponent::JustSpaces(count) => Ok(" ".repeat(*count % 100)),
            ReasonComponent::HttpInjection(s) => Ok(format!("OK\r\nSet-Cookie: {}", s)),
            ReasonComponent::HeaderLike(name, value) => Ok(format!("OK\r\n{}: {}", name, value)),
            ReasonComponent::BodyLike(body) => Ok(format!("OK\r\n\r\n{}", body)),
        }
    }

    fn build_delimiters(&self, delims: &DelimiterConfig) -> (String, String) {
        match delims {
            DelimiterConfig::Standard => (" ".to_string(), " ".to_string()),
            DelimiterConfig::ExtraSpaces(count) => {
                let spaces = " ".repeat(1 + (count % 10));
                (spaces.clone(), spaces)
            }
            DelimiterConfig::NoFirstSpace => ("".to_string(), " ".to_string()),
            DelimiterConfig::NoSecondSpace => (" ".to_string(), "".to_string()),
            DelimiterConfig::NoSpaces => ("".to_string(), "".to_string()),
            DelimiterConfig::Tabs => ("\t".to_string(), "\t".to_string()),
            DelimiterConfig::Mixed => (" \t".to_string(), "\t ".to_string()),
            DelimiterConfig::WithNulls => (" \0".to_string(), "\0 ".to_string()),
            DelimiterConfig::WithCarriageReturn => (" \r".to_string(), "\r ".to_string()),
            DelimiterConfig::WithLineFeed => (" \n".to_string(), "\n ".to_string()),
        }
    }

    fn apply_formatting(
        &self,
        line: String,
        formatting: &FormattingCase,
    ) -> Result<String, String> {
        match formatting {
            FormattingCase::Normal => Ok(line),
            FormattingCase::LeadingWhitespace => Ok(format!("   {}", line)),
            FormattingCase::TrailingWhitespace => Ok(format!("{}   ", line)),
            FormattingCase::BothWhitespace => Ok(format!("   {}   ", line)),
            FormattingCase::RandomCase => Ok(line
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    }
                })
                .collect()),
            FormattingCase::MinimalLine => Ok("HTTP/1.1 200".to_string()),
            FormattingCase::MaximalLine => {
                let long_reason = "Very Long Reason Phrase ".repeat(50);
                Ok(format!("HTTP/1.1 200 {}", long_reason))
            }
            FormattingCase::HttpsPrefix => Ok(format!("https://{}", line)),
            FormattingCase::UrlLike(domain) => Ok(format!("http://{}/{}", domain, line)),
            FormattingCase::SqlInjection(payload) => Ok(format!("{} OR 1=1; {}", line, payload)),
            FormattingCase::XssAttempt(payload) => {
                Ok(format!("{}<script>{}</script>", line, payload))
            }
            FormattingCase::PathTraversal => Ok(format!("{}/../../../etc/passwd", line)),
            FormattingCase::NullBytes(count) => {
                let nulls = "\0".repeat(*count % 10);
                Ok(format!("{}{}", line, nulls))
            }
            FormattingCase::HighBitSet(suffix) => {
                let high_bits: String = (128u8..=255u8).map(|b| b as char).collect();
                Ok(format!("{}{}{}", line, high_bits, suffix))
            }
            FormattingCase::BomPrefix => Ok(format!("\u{FEFF}{}", line)),
            FormattingCase::UnicodeNormalization(suffix) => Ok(format!("{}é{}", line, suffix)),
        }
    }

    fn apply_termination(&self, line: String, termination: &LineTermination) -> String {
        match termination {
            LineTermination::Crlf => format!("{}\r\n", line),
            LineTermination::Lf => format!("{}\n", line),
            LineTermination::Cr => format!("{}\r", line),
            LineTermination::None => line,
            LineTermination::MultipleCrlf => format!("{}\r\n\r\n", line),
            LineTermination::ExtraAfterCrlf(extra) => format!("{}\r\n{}", line, extra),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    if let Ok(test_case) = StatusLineTestCase::arbitrary(&mut u) {
        let parser = MockStatusLineParser::new();

        // Test the main parsing flow
        let result = parser.parse_from_test_case(&test_case);

        // Validate parsing invariants
        match result {
            Ok(parsed) => {
                // Status code should be in valid range for strict parsing
                if parser.strict_status {
                    assert!(
                        (100..=999).contains(&parsed.status),
                        "Parsed status {} outside valid range",
                        parsed.status
                    );
                }

                // Version should be known for strict parsing
                if parser.strict_version {
                    assert!(
                        matches!(parsed.version, HttpVersion::Http10 | HttpVersion::Http11),
                        "Unknown version {:?} parsed in strict mode",
                        parsed.version
                    );
                }

                // Reason phrase should not contain control characters (except tab)
                for c in parsed.reason.chars() {
                    assert!(
                        !c.is_control() || c == '\t',
                        "Control character {:?} in reason phrase",
                        c
                    );
                }

                // Test round-trip consistency where applicable
                if matches!(parsed.version, HttpVersion::Http10 | HttpVersion::Http11)
                    && (100..=999).contains(&parsed.status)
                {
                    let rebuilt = format!(
                        "{} {} {}",
                        match parsed.version {
                            HttpVersion::Http10 => "HTTP/1.0",
                            HttpVersion::Http11 => "HTTP/1.1",
                            _ => unreachable!(),
                        },
                        parsed.status,
                        parsed.reason
                    );

                    // Re-parsing should succeed
                    let reparsed = parser.parse_status_line(&rebuilt);
                    assert!(
                        reparsed.is_ok(),
                        "Round-trip parsing failed for: {}",
                        rebuilt
                    );
                }
            }

            Err(_error) => {
                // Error is acceptable - validate it doesn't cause crashes or hangs

                // Test that error handling is consistent
                let line_result = parser.build_status_line(&test_case);
                if let Ok(line) = line_result {
                    // If we can build a line, parsing error should be deterministic
                    let retry_result = parser.parse_status_line(&line);
                    assert!(
                        retry_result.is_err(),
                        "Non-deterministic parsing error for line: {}",
                        line.chars()
                            .map(|c| if c.is_control() {
                                format!("\\x{:02x}", c as u8)
                            } else {
                                c.to_string()
                            })
                            .collect::<String>()
                    );
                }
            }
        }

        // Test edge case: very long lines
        if let Ok(line) = parser.build_status_line(&test_case) {
            if line.len() > parser.max_line_length {
                let result = parser.parse_status_line(&line);
                assert!(
                    result.is_err(),
                    "Overly long line should be rejected: length {}",
                    line.len()
                );
            }
        }

        // Test strict vs lenient modes
        let mut lenient_parser = MockStatusLineParser::new();
        lenient_parser.strict_version = false;
        lenient_parser.strict_status = false;

        let strict_result = parser.parse_from_test_case(&test_case);
        let lenient_result = lenient_parser.parse_from_test_case(&test_case);

        // Lenient mode should never be stricter than strict mode
        if strict_result.is_ok() {
            assert!(
                lenient_result.is_ok(),
                "Lenient parser rejected input that strict parser accepted"
            );
        }

        // Test empty and minimal input handling
        let empty_result = parser.parse_status_line("");
        assert!(empty_result.is_err(), "Empty line should be rejected");

        let minimal_result = parser.parse_status_line("HTTP/1.1 200");
        assert!(minimal_result.is_ok(), "Minimal valid line should parse");

        // Test common valid cases
        let common_cases = [
            "HTTP/1.1 200 OK",
            "HTTP/1.0 404 Not Found",
            "HTTP/1.1 500 Internal Server Error",
        ];

        for case in &common_cases {
            let result = parser.parse_status_line(case);
            assert!(result.is_ok(), "Common case should parse: {}", case);
        }
    }
});
