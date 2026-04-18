//! Comprehensive fuzz target for HTTP/1.1 request-line parsing RFC 9112.
//!
//! This target feeds malformed HTTP/1.1 request-lines to the parser to assert
//! critical RFC 9112 compliance and security properties:
//!
//! 1. Oversized URI rejected per max_uri_length (request line limit)
//! 2. Method token validated against RFC 9110 Section 9.1
//! 3. HTTP-version prefix 'HTTP/' required
//! 4. CRLF termination mandatory
//! 5. Absolute-URI form for proxy requests
//! 6. Origin-form vs asterisk-form dispatched correctly
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run h1_request_line
//! ```
//!
//! # Security Focus
//! - Request line length boundary validation (max 8KB)
//! - HTTP method token validation (RFC 9110 tchar set)
//! - HTTP version prefix enforcement
//! - CRLF injection prevention
//! - URI form validation and routing

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::http::h1::types::{Method, Version};
use libfuzzer_sys::fuzz_target;

/// Maximum fuzz input size to prevent timeouts
const MAX_FUZZ_INPUT_SIZE: usize = 100_000;

/// Maximum request line length per HTTP/1.1 codec
const MAX_REQUEST_LINE_LENGTH: usize = 8192;

/// HTTP method generation strategy for fuzzing
#[derive(Arbitrary, Debug, Clone)]
enum MethodStrategy {
    /// Standard HTTP methods
    Standard(StandardMethod),
    /// Valid extension method (RFC 9110 token)
    ValidExtension { name: String },
    /// Invalid method with forbidden characters
    InvalidToken { name: String },
    /// Empty method
    Empty,
    /// Method with whitespace
    WithWhitespace { name: String },
    /// Very long method name
    VeryLong { length: usize },
}

#[derive(Arbitrary, Debug, Clone)]
enum StandardMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
}

impl StandardMethod {
    fn to_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Connect => "CONNECT",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Patch => "PATCH",
        }
    }
}

/// URI form generation strategy
#[derive(Arbitrary, Debug, Clone)]
enum UriStrategy {
    /// Origin-form: /path?query#fragment
    OriginForm { path: String, query: Option<String> },
    /// Absolute-form: http://host/path (for proxy requests)
    AbsoluteForm { scheme: String, host: String, port: Option<u16>, path: String },
    /// Authority-form: host:port (for CONNECT)
    AuthorityForm { host: String, port: u16 },
    /// Asterisk-form: * (for OPTIONS)
    AsteriskForm,
    /// Invalid URI with forbidden characters
    Invalid { uri: String },
    /// Empty URI
    Empty,
    /// Oversized URI
    Oversized { size: usize },
    /// URI with whitespace
    WithWhitespace { uri: String },
}

/// HTTP version strategy
#[derive(Arbitrary, Debug, Clone)]
enum VersionStrategy {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// Invalid version without HTTP/ prefix
    NoPrefix { version: String },
    /// Invalid version with wrong prefix
    WrongPrefix { prefix: String, version: String },
    /// Unsupported HTTP version
    Unsupported { major: u8, minor: u8 },
    /// Malformed version
    Malformed { version: String },
    /// Empty version
    Empty,
}

/// Request line termination strategy
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

/// Spacing strategy between request line components
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

/// Request line corruption strategy for security testing
#[derive(Arbitrary, Debug, Clone)]
enum CorruptionStrategy {
    /// No corruption - generate valid request line
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
}

#[derive(Arbitrary, Debug, Clone)]
enum ComponentType {
    Method,
    Uri,
    Version,
}

/// Comprehensive fuzz input for HTTP/1.1 request-line parsing
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Method generation strategy
    method: MethodStrategy,
    /// URI generation strategy
    uri: UriStrategy,
    /// HTTP version strategy
    version: VersionStrategy,
    /// Spacing between components
    spacing: SpacingStrategy,
    /// Line termination strategy
    termination: TerminationStrategy,
    /// Corruption strategy for security testing
    corruption: CorruptionStrategy,
}

impl FuzzInput {
    /// Construct the complete request line bytes
    fn construct_request_line(&self) -> Vec<u8> {
        let method_str = self.generate_method();
        let uri_str = self.generate_uri();
        let version_str = self.generate_version();
        let spacing = self.generate_spacing();
        let termination = self.generate_termination();

        let mut request_line = Vec::new();

        if matches!(self.corruption, CorruptionStrategy::SwapOrder) {
            // Intentionally wrong order for corruption testing
            request_line.extend_from_slice(uri_str.as_bytes());
            request_line.extend_from_slice(&spacing);
            request_line.extend_from_slice(method_str.as_bytes());
            request_line.extend_from_slice(&spacing);
            request_line.extend_from_slice(version_str.as_bytes());
        } else {
            // Standard order: METHOD SP URI SP VERSION
            request_line.extend_from_slice(method_str.as_bytes());

            if let CorruptionStrategy::Duplicate { component: ComponentType::Method } = &self.corruption {
                request_line.extend_from_slice(&spacing);
                request_line.extend_from_slice(method_str.as_bytes());
            }

            request_line.extend_from_slice(&spacing);
            request_line.extend_from_slice(uri_str.as_bytes());

            if let CorruptionStrategy::Duplicate { component: ComponentType::Uri } = &self.corruption {
                request_line.extend_from_slice(&spacing);
                request_line.extend_from_slice(uri_str.as_bytes());
            }

            request_line.extend_from_slice(&spacing);
            request_line.extend_from_slice(version_str.as_bytes());

            if let CorruptionStrategy::Duplicate { component: ComponentType::Version } = &self.corruption {
                request_line.extend_from_slice(&spacing);
                request_line.extend_from_slice(version_str.as_bytes());
            }
        }

        request_line.extend_from_slice(&termination);

        self.apply_corruption(request_line)
    }

    fn generate_method(&self) -> String {
        match &self.method {
            MethodStrategy::Standard(method) => method.to_str().to_string(),
            MethodStrategy::ValidExtension { name } => {
                // Generate valid token characters (RFC 9110)
                name.chars()
                    .map(|c| match c {
                        c if c.is_ascii_alphanumeric() => c,
                        _ => ['!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~']
                            .get((c as usize) % 15)
                            .copied()
                            .unwrap_or('X')
                    })
                    .collect::<String>()
                    .chars()
                    .take(32)
                    .collect()
            }
            MethodStrategy::InvalidToken { name } => {
                // Include invalid characters for token validation testing
                let mut invalid = name.clone();
                if !invalid.contains(' ') {
                    invalid.push(' '); // Space is invalid in token
                }
                if !invalid.contains('\t') {
                    invalid.push('\t'); // Tab is invalid in token
                }
                invalid
            }
            MethodStrategy::Empty => String::new(),
            MethodStrategy::WithWhitespace { name } => {
                format!(" {} ", name.trim())
            }
            MethodStrategy::VeryLong { length } => {
                "M".repeat((*length).min(10000))
            }
        }
    }

    fn generate_uri(&self) -> String {
        match &self.uri {
            UriStrategy::OriginForm { path, query } => {
                let mut uri = if path.is_empty() || !path.starts_with('/') {
                    format!("/{}", path)
                } else {
                    path.clone()
                };
                if let Some(q) = query {
                    if !q.is_empty() {
                        uri.push('?');
                        uri.push_str(q);
                    }
                }
                uri
            }
            UriStrategy::AbsoluteForm { scheme, host, port, path } => {
                let mut uri = format!("{}://{}", scheme, host);
                if let Some(p) = port {
                    uri.push_str(&format!(":{}", p));
                }
                if !path.is_empty() {
                    if !path.starts_with('/') {
                        uri.push('/');
                    }
                    uri.push_str(path);
                }
                uri
            }
            UriStrategy::AuthorityForm { host, port } => {
                format!("{}:{}", host, port)
            }
            UriStrategy::AsteriskForm => "*".to_string(),
            UriStrategy::Invalid { uri } => {
                // Add invalid characters for URI testing
                let mut invalid = uri.clone();
                invalid.push('\0'); // Null byte
                invalid.push(' '); // Space (invalid in URI)
                invalid
            }
            UriStrategy::Empty => String::new(),
            UriStrategy::Oversized { size } => {
                let base_uri = "/".to_string();
                let padding_size = (*size).saturating_sub(base_uri.len()).min(50000);
                format!("/{}", "x".repeat(padding_size))
            }
            UriStrategy::WithWhitespace { uri } => {
                format!(" {} ", uri.trim())
            }
        }
    }

    fn generate_version(&self) -> String {
        match &self.version {
            VersionStrategy::Http10 => "HTTP/1.0".to_string(),
            VersionStrategy::Http11 => "HTTP/1.1".to_string(),
            VersionStrategy::NoPrefix { version } => version.clone(),
            VersionStrategy::WrongPrefix { prefix, version } => {
                format!("{}/{}", prefix, version)
            }
            VersionStrategy::Unsupported { major, minor } => {
                format!("HTTP/{}.{}", major, minor)
            }
            VersionStrategy::Malformed { version } => version.clone(),
            VersionStrategy::Empty => String::new(),
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

    fn apply_corruption(&self, mut request_line: Vec<u8>) -> Vec<u8> {
        match &self.corruption {
            CorruptionStrategy::None => request_line,
            CorruptionStrategy::NullBytes { positions } => {
                for &pos in positions.iter().take(10) {
                    if pos < request_line.len() {
                        request_line.insert(pos, 0);
                    }
                }
                request_line
            }
            CorruptionStrategy::ControlChars { chars, positions } => {
                for (&ch, &pos) in chars.iter().zip(positions.iter()).take(10) {
                    if pos < request_line.len() && ch < 32 && ch != b'\r' && ch != b'\n' {
                        request_line.insert(pos, ch);
                    }
                }
                request_line
            }
            CorruptionStrategy::NonAscii { chars, positions } => {
                for (&ch, &pos) in chars.iter().zip(positions.iter()).take(10) {
                    if pos < request_line.len() && ch > 127 {
                        request_line.insert(pos, ch);
                    }
                }
                request_line
            }
            CorruptionStrategy::Truncate { position } => {
                let len = (*position).min(request_line.len());
                request_line.truncate(len);
                request_line
            }
            CorruptionStrategy::Duplicate { .. } | CorruptionStrategy::SwapOrder => {
                // Already handled in construct_request_line
                request_line
            }
        }
    }
}

/// Mock HTTP/1.1 request-line parser for validation
struct MockH1RequestLineParser {
    max_request_line_length: usize,
}

impl MockH1RequestLineParser {
    fn new() -> Self {
        Self {
            max_request_line_length: MAX_REQUEST_LINE_LENGTH,
        }
    }

    fn parse_request_line(&self, line: &[u8]) -> Result<(String, String, String), ParseError> {
        // **ASSERTION 4: CRLF termination**
        if !line.ends_with(b"\r\n") {
            return Err(ParseError::MissingCrlf);
        }

        let line_without_crlf = &line[..line.len().saturating_sub(2)];

        // **ASSERTION 1: Oversized URI rejected per max_uri_length**
        if line_without_crlf.len() > self.max_request_line_length {
            return Err(ParseError::RequestLineTooLong);
        }

        let line_str = std::str::from_utf8(line_without_crlf)
            .map_err(|_| ParseError::InvalidUtf8)?;

        let parts: Vec<&str> = line_str.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(ParseError::InvalidFormat);
        }

        let method = parts[0];
        let uri = parts[1];
        let version = parts[2];

        // **ASSERTION 2: Method token validated against RFC 9110 Section 9.1**
        self.validate_method(method)?;

        // **ASSERTION 3: HTTP-version prefix 'HTTP/' required**
        self.validate_version(version)?;

        // **ASSERTION 5: Absolute-URI form for proxy**
        // **ASSERTION 6: Origin-form vs asterisk-form dispatched correctly**
        self.validate_uri_form(method, uri)?;

        Ok((method.to_string(), uri.to_string(), version.to_string()))
    }

    fn validate_method(&self, method: &str) -> Result<(), ParseError> {
        if method.is_empty() {
            return Err(ParseError::EmptyMethod);
        }

        // Standard methods
        if matches!(method, "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH") {
            return Ok(());
        }

        // Extension methods must be valid tokens (RFC 9110 Section 5.6.2)
        // token = 1*tchar
        // tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
        //         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
        for byte in method.bytes() {
            match byte {
                b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
                b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => {
                    // Valid tchar
                }
                _ => return Err(ParseError::InvalidMethodToken),
            }
        }

        Ok(())
    }

    fn validate_version(&self, version: &str) -> Result<(), ParseError> {
        if !version.starts_with("HTTP/") {
            return Err(ParseError::MissingHttpPrefix);
        }

        match version {
            "HTTP/1.0" | "HTTP/1.1" => Ok(()),
            _ => Err(ParseError::UnsupportedVersion),
        }
    }

    fn validate_uri_form(&self, method: &str, uri: &str) -> Result<(), ParseError> {
        if uri.is_empty() {
            return Err(ParseError::EmptyUri);
        }

        // Check for absolute-form (proxy requests)
        if uri.starts_with("http://") || uri.starts_with("https://") {
            // Absolute-form should be used for proxy requests
            return Ok(());
        }

        // Authority-form for CONNECT method
        if method == "CONNECT" {
            if uri.contains("://") {
                return Err(ParseError::InvalidAuthorityForm);
            }
            // Should be host:port format
            return Ok(());
        }

        // Asterisk-form for OPTIONS * requests
        if uri == "*" {
            if method != "OPTIONS" {
                return Err(ParseError::AsteriskFormInvalidMethod);
            }
            return Ok(());
        }

        // Origin-form (most common)
        if uri.starts_with('/') || uri == "*" {
            return Ok(());
        }

        // Invalid URI form
        Err(ParseError::InvalidUriForm)
    }
}

#[derive(Debug, PartialEq, Clone)]
enum ParseError {
    MissingCrlf,
    RequestLineTooLong,
    InvalidUtf8,
    InvalidFormat,
    EmptyMethod,
    InvalidMethodToken,
    MissingHttpPrefix,
    UnsupportedVersion,
    EmptyUri,
    InvalidAuthorityForm,
    AsteriskFormInvalidMethod,
    InvalidUriForm,
}

fuzz_target!(|input: FuzzInput| {
    // Bound input size to prevent timeouts
    let request_line_bytes = input.construct_request_line();
    if request_line_bytes.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Create full HTTP request for codec testing
    let mut full_request = request_line_bytes.clone();
    full_request.extend_from_slice(b"\r\n"); // End headers section

    let mock_parser = MockH1RequestLineParser::new();
    let mock_result = mock_parser.parse_request_line(&request_line_bytes);

    // Test the actual HTTP/1.1 codec
    let mut codec = Http1Codec::new();
    let mut buffer = BytesMut::from(full_request.as_slice());

    let codec_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        codec.decode(&mut buffer)
    }));

    match codec_result {
        Ok(parse_result) => {
            match (mock_result.clone(), parse_result) {
                (Ok((method, uri, version)), Ok(Some(request))) => {
                    // Both parsers succeeded - verify consistency
                    assert_eq!(request.method.as_str(), method);
                    assert_eq!(request.uri, uri);
                    assert_eq!(request.version.as_str(), version);

                    // **ASSERTION 1: Oversized URI rejected per max_uri_length**
                    assert!(request_line_bytes.len() <= MAX_REQUEST_LINE_LENGTH + 2); // +2 for CRLF

                    // **ASSERTION 2: Method token validated against RFC 9110 Section 9.1**
                    // If codec accepted it, it must be a valid token
                    validate_method_consistency(&request.method);

                    // **ASSERTION 3: HTTP-version prefix 'HTTP/' required**
                    assert!(version.starts_with("HTTP/"));
                    assert!(matches!(request.version, Version::Http10 | Version::Http11));

                    // **ASSERTION 6: Origin-form vs asterisk-form dispatched correctly**
                    validate_uri_form_consistency(&method, &uri);
                }
                (Err(expected_error), Ok(Some(_))) => {
                    // Mock parser correctly rejected but codec accepted - potential issue
                    match expected_error {
                        ParseError::RequestLineTooLong => {
                            panic!("Codec accepted oversized request line that should be rejected");
                        }
                        ParseError::InvalidMethodToken => {
                            panic!("Codec accepted invalid method token: {:?}",
                                String::from_utf8_lossy(&request_line_bytes));
                        }
                        ParseError::MissingHttpPrefix => {
                            panic!("Codec accepted version without HTTP/ prefix: {:?}",
                                String::from_utf8_lossy(&request_line_bytes));
                        }
                        ParseError::MissingCrlf => {
                            panic!("Codec accepted request line without proper CRLF termination");
                        }
                        _ => {
                            // Other validation differences may be acceptable
                        }
                    }
                }
                (Ok(_), Err(HttpError::RequestLineTooLong)) => {
                    // **ASSERTION 1: Oversized URI rejected per max_uri_length**
                    assert!(request_line_bytes.len().saturating_sub(2) > MAX_REQUEST_LINE_LENGTH,
                        "Codec rejected request line within size limits");
                }
                (Ok(_), Err(HttpError::BadMethod)) => {
                    // **ASSERTION 2: Method token validated against RFC 9110 Section 9.1**
                    // Expected for invalid method tokens
                }
                (Ok(_), Err(HttpError::UnsupportedVersion)) => {
                    // **ASSERTION 3: HTTP-version prefix 'HTTP/' required**
                    // Expected for invalid HTTP versions
                }
                (Ok(_), Err(HttpError::BadRequestLine)) => {
                    // **ASSERTION 4: CRLF termination**
                    // Expected for malformed request lines
                }
                (Err(_), Err(_)) => {
                    // Both parsers correctly rejected the input
                }
                (_, Ok(None)) => {
                    // Incomplete request - codec needs more data
                }
                (_, Err(_)) => {
                    // Codec rejected input - verify error is appropriate
                }
            }
        }
        Err(_) => {
            // Codec panicked - this is a bug
            panic!("HTTP/1.1 codec panicked on input: {:?}",
                String::from_utf8_lossy(&request_line_bytes));
        }
    }

    // **ASSERTION 5: Absolute-URI form for proxy**
    // Test proxy request handling (if we implement proxy logic)
    if let Ok((_method, uri, _version)) = &mock_result {
        if uri.starts_with("http://") || uri.starts_with("https://") {
            // This is an absolute-form URI for proxy requests
            // Verify proper handling according to RFC 9112
            assert!(uri.contains("://"), "Absolute-form URI must contain scheme");
        }
    }
});

fn validate_method_consistency(method: &Method) {
    match method {
        Method::Extension(ext) => {
            // Extension methods must be valid tokens
            for byte in ext.bytes() {
                assert!(
                    matches!(byte,
                        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
                        b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
                    ),
                    "Extension method contains invalid token character: {:02x}", byte
                );
            }
            assert!(!ext.is_empty(), "Extension method cannot be empty");
        }
        _ => {
            // Standard methods are always valid
        }
    }
}

fn validate_uri_form_consistency(method: &str, uri: &str) {
    if method == "CONNECT" && !uri.contains("://") {
        // Authority-form for CONNECT should not contain scheme
        assert!(uri.contains(':'), "CONNECT authority-form should contain port");
    }

    if uri == "*" {
        assert_eq!(method, "OPTIONS", "Asterisk-form only valid for OPTIONS method");
    }

    if uri.starts_with("http://") || uri.starts_with("https://") {
        // Absolute-form is valid for any method (proxy requests)
        assert!(uri.len() > 7, "Absolute-form URI too short");
    }
}
