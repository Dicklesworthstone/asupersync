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
/// Maximum header block size per HTTP/1.1 codec
const MAX_HEADERS_SIZE: usize = 64 * 1024;
/// Maximum number of headers per HTTP/1.1 codec
const MAX_HEADERS: usize = 128;

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
    AbsoluteForm {
        scheme: String,
        host: String,
        port: Option<u16>,
        path: String,
    },
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
}

#[derive(Arbitrary, Debug, Clone)]
enum ComponentType {
    Method,
    Uri,
    Version,
}

/// Header field used for valid header-block generation.
#[derive(Arbitrary, Debug, Clone)]
struct HeaderField {
    name: String,
    value: String,
}

/// Header block generation strategy.
#[derive(Arbitrary, Debug, Clone)]
enum HeaderStrategy {
    /// No headers, only the terminating CRLF.
    None,
    /// A small, valid header block.
    Valid { headers: Vec<HeaderField> },
    /// Obsolete line folding continuation that modern parsers must reject.
    FoldedContinuation {
        name: String,
        value: String,
        continuation: String,
        tab_prefix: bool,
    },
    /// A header block that exceeds the codec's size limit.
    Oversized { size: usize },
    /// A header block that exceeds the codec's header-count limit.
    TooMany { extra: u8 },
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
    /// Header block generation strategy
    headers: HeaderStrategy,
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

            if let CorruptionStrategy::Duplicate {
                component: ComponentType::Method,
            } = &self.corruption
            {
                request_line.extend_from_slice(&spacing);
                request_line.extend_from_slice(method_str.as_bytes());
            }

            request_line.extend_from_slice(&spacing);
            request_line.extend_from_slice(uri_str.as_bytes());

            if let CorruptionStrategy::Duplicate {
                component: ComponentType::Uri,
            } = &self.corruption
            {
                request_line.extend_from_slice(&spacing);
                request_line.extend_from_slice(uri_str.as_bytes());
            }

            request_line.extend_from_slice(&spacing);
            request_line.extend_from_slice(version_str.as_bytes());

            if let CorruptionStrategy::Duplicate {
                component: ComponentType::Version,
            } = &self.corruption
            {
                request_line.extend_from_slice(&spacing);
                request_line.extend_from_slice(version_str.as_bytes());
            }
        }

        request_line.extend_from_slice(&termination);

        self.apply_corruption(request_line)
    }

    fn construct_headers(&self) -> Vec<u8> {
        match &self.headers {
            HeaderStrategy::None => Vec::new(),
            HeaderStrategy::Valid { headers } => {
                let mut block = Vec::new();
                for header in headers.iter().take(16) {
                    let name = sanitize_header_name(&header.name);
                    let value = sanitize_header_value(&header.value);
                    block.extend_from_slice(name.as_bytes());
                    block.extend_from_slice(b": ");
                    block.extend_from_slice(value.as_bytes());
                    block.extend_from_slice(b"\r\n");
                }
                block
            }
            HeaderStrategy::FoldedContinuation {
                name,
                value,
                continuation,
                tab_prefix,
            } => {
                let mut block = Vec::new();
                let name = sanitize_header_name(name);
                let value = sanitize_header_value(value);
                let continuation = sanitize_header_value(continuation);
                let prefix = if *tab_prefix { b'\t' } else { b' ' };
                block.extend_from_slice(name.as_bytes());
                block.extend_from_slice(b": ");
                block.extend_from_slice(value.as_bytes());
                block.extend_from_slice(b"\r\n");
                block.push(prefix);
                block.extend_from_slice(continuation.as_bytes());
                block.extend_from_slice(b"\r\n");
                block
            }
            HeaderStrategy::Oversized { size } => {
                let value_len = (*size).clamp(MAX_HEADERS_SIZE + 1, MAX_FUZZ_INPUT_SIZE / 2);
                let mut block = b"X-Fuzz: ".to_vec();
                block.extend(std::iter::repeat_n(b'a', value_len));
                block.extend_from_slice(b"\r\n");
                block
            }
            HeaderStrategy::TooMany { extra } => {
                let header_count = MAX_HEADERS + 1 + usize::from(*extra % 16);
                let mut block = Vec::with_capacity(header_count * 12);
                for idx in 0..header_count {
                    block.extend_from_slice(format!("X-{idx}: v\r\n").as_bytes());
                }
                block
            }
        }
    }

    fn expected_header_count(&self) -> Option<usize> {
        match &self.headers {
            HeaderStrategy::None => Some(0),
            HeaderStrategy::Valid { headers } => Some(headers.len().min(16)),
            HeaderStrategy::FoldedContinuation { .. }
            | HeaderStrategy::Oversized { .. }
            | HeaderStrategy::TooMany { .. } => None,
        }
    }

    fn generate_method(&self) -> String {
        match &self.method {
            MethodStrategy::Standard(method) => method.to_str().to_string(),
            MethodStrategy::ValidExtension { name } => {
                // Generate valid token characters (RFC 9110)
                name.chars()
                    .map(|c| match c {
                        c if c.is_ascii_alphanumeric() => c,
                        _ => [
                            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|',
                            '~',
                        ]
                        .get((c as usize) % 15)
                        .copied()
                        .unwrap_or('X'),
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
            MethodStrategy::VeryLong { length } => "M".repeat((*length).min(10000)),
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
                if let Some(q) = query
                    && !q.is_empty()
                {
                    uri.push('?');
                    uri.push_str(q);
                }
                uri
            }
            UriStrategy::AbsoluteForm {
                scheme,
                host,
                port,
                path,
            } => {
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

fn sanitize_header_name(name: &str) -> String {
    let mut cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(32)
        .collect();

    if cleaned.is_empty() {
        cleaned.push_str("x-fuzz");
    }
    if cleaned.eq_ignore_ascii_case("content-length")
        || cleaned.eq_ignore_ascii_case("transfer-encoding")
    {
        cleaned.insert_str(0, "x-");
    }
    cleaned
}

fn sanitize_header_value(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii() && !matches!(c, '\r' | '\n'))
        .take(128)
        .collect();

    if cleaned.is_empty() {
        "ok".to_string()
    } else {
        cleaned
    }
}

fn request_line_content_len(line: &[u8]) -> Option<usize> {
    line.strip_suffix(b"\r\n").map(<[u8]>::len)
}

fuzz_target!(|input: FuzzInput| {
    // Bound input size to prevent timeouts
    let request_line_bytes = input.construct_request_line();
    let header_bytes = input.construct_headers();
    if request_line_bytes.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Create full HTTP request for codec testing
    let mut full_request = request_line_bytes.clone();
    full_request.extend_from_slice(&header_bytes);
    full_request.extend_from_slice(b"\r\n"); // End headers section
    if full_request.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }
    let full_request_len = full_request.len();

    // Test the actual HTTP/1.1 codec
    let mut codec = Http1Codec::new();
    let mut buffer = BytesMut::from(full_request.as_slice());

    let codec_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| codec.decode(&mut buffer)));

    match codec_result {
        Ok(parse_result) => match parse_result {
            Ok(Some(request)) => {
                let request_line_len = request_line_content_len(&request_line_bytes)
                    .expect("accepted request line must use CRLF termination");

                // **ASSERTION 1: Oversized URI rejected per max_uri_length**
                assert!(
                    request_line_len <= MAX_REQUEST_LINE_LENGTH,
                    "Codec accepted oversized request line: {request_line_len}"
                );

                // **ASSERTION 2: Method token validated against RFC 9110 Section 9.1**
                validate_method_consistency(&request.method);

                // **ASSERTION 3: HTTP-version prefix 'HTTP/' required**
                assert!(matches!(request.version, Version::Http10 | Version::Http11));
                assert!(request.version.as_str().starts_with("HTTP/"));

                // **ASSERTION 4: CRLF termination**
                assert!(
                    request_line_bytes.ends_with(b"\r\n"),
                    "Codec accepted request line without CRLF termination"
                );

                // **ASSERTION 5 + 6: URI forms stay consistent with the real parsed request**
                validate_uri_form_consistency(request.method.as_str(), &request.uri);

                assert!(
                    !matches!(input.headers, HeaderStrategy::FoldedContinuation { .. }),
                    "Codec accepted obsolete folded continuation header: {:?}",
                    String::from_utf8_lossy(&full_request)
                );
                assert!(
                    !matches!(input.headers, HeaderStrategy::Oversized { .. }),
                    "Codec accepted oversized header block"
                );
                assert!(
                    !matches!(input.headers, HeaderStrategy::TooMany { .. }),
                    "Codec accepted header count above configured limit"
                );

                if let Some(expected_header_count) = input.expected_header_count() {
                    assert_eq!(request.headers.len(), expected_header_count);
                }
            }
            Err(HttpError::RequestLineTooLong) => {
                // **ASSERTION 1: Oversized URI rejected per max_uri_length**
                assert!(
                    request_line_content_len(&request_line_bytes)
                        .is_some_and(|len| len > MAX_REQUEST_LINE_LENGTH),
                    "Codec rejected request line within size limits"
                );
            }
            Err(HttpError::HeadersTooLarge) => {
                assert!(
                    matches!(input.headers, HeaderStrategy::Oversized { .. })
                        || full_request_len > MAX_HEADERS_SIZE,
                    "Codec rejected a header block within configured size limits"
                );
            }
            Err(HttpError::TooManyHeaders) => {
                assert!(
                    matches!(input.headers, HeaderStrategy::TooMany { .. }),
                    "Codec reported too many headers without a generated overrun"
                );
            }
            Err(HttpError::BadRequestLine) => {
                // Malformed request-line layouts are expected to fail here.
            }
            Ok(None) | Err(_) => {
                // Incomplete input or a parser rejection on malformed fuzz data is acceptable.
            }
        },
        Err(_) => {
            // Codec panicked - this is a bug
            panic!(
                "HTTP/1.1 codec panicked on input: {:?}",
                String::from_utf8_lossy(&request_line_bytes)
            );
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
                    "Extension method contains invalid token character: {:02x}",
                    byte
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
        assert!(
            uri.contains(':'),
            "CONNECT authority-form should contain port"
        );
    }

    if uri == "*" {
        assert_eq!(
            method, "OPTIONS",
            "Asterisk-form only valid for OPTIONS method"
        );
    }

    if uri.starts_with("http://") || uri.starts_with("https://") {
        // Absolute-form is valid for any method (proxy requests)
        assert!(uri.len() > 7, "Absolute-form URI too short");
    }
}
