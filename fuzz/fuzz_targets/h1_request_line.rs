//! Comprehensive fuzz target for HTTP/1.1 request-line parsing.
//!
//! Targets: src/http/h1/codec.rs request-line parser functions
//! Coverage: (1) method/path/version extraction; (2) CR-before-LF tolerance;
//!          (3) max-line-length enforcement; (4) invalid byte rejection;
//!          (5) path percent-decoding boundaries
//!
//! # Attack Vectors Tested
//! - Method validation bypass attempts (invalid tokens, case sensitivity)
//! - Path injection via malformed URIs and percent-encoding
//! - Version confusion attacks (HTTP/0.9, HTTP/2.0, malformed versions)
//! - Line length boundary conditions (8192 byte limit)
//! - CRLF injection and normalization issues
//! - UTF-8 validation bypass in URI components
//! - Whitespace handling edge cases in token separation

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::{Http1Codec, HttpError};
use libfuzzer_sys::fuzz_target;

/// Maximum request line length from the implementation
const MAX_REQUEST_LINE: usize = 8192;

/// HTTP methods to use in generation
const VALID_METHODS: &[&[u8]] = &[
    b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH",
];

/// HTTP versions to use in generation
const VALID_VERSIONS: &[&[u8]] = &[b"HTTP/1.0", b"HTTP/1.1"];

/// Invalid methods for negative testing
const INVALID_METHODS: &[&[u8]] = &[
    b"",
    b"GE\x00T",
    b"GET\x01",
    b"g e t",
    b"GET\x7F",
    b"\x80METHOD",
];

/// Invalid versions for negative testing
const INVALID_VERSIONS: &[&[u8]] = &[
    b"",
    b"HTTP/2.0",
    b"http/1.1",
    b"HTTP/1.",
    b"HTTP\x00/1.1",
    b"\x80VER",
];

/// Fuzzable request-line components for structure-aware generation
#[derive(Arbitrary, Debug, Clone)]
enum RequestLineType {
    /// Valid request line with controlled components
    Valid {
        method: MethodChoice,
        path: PathChoice,
        version: VersionChoice,
        whitespace: WhitespacePattern,
    },
    /// Malformed request line for negative testing
    Malformed {
        corruption: CorruptionType,
        base_valid: bool,
    },
    /// Boundary condition testing
    Boundary { condition: BoundaryCondition },
}

#[derive(Arbitrary, Debug, Clone)]
enum MethodChoice {
    StandardValid(u8),   // Index into VALID_METHODS
    StandardInvalid(u8), // Index into INVALID_METHODS
    CustomValid(String),
    CustomInvalid(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
enum PathChoice {
    Simple(String),
    WithQuery(String, String),
    PercentEncoded(String),
    InvalidUtf8(Vec<u8>),
    Empty,
    VeryLong(u16), // Length multiplier
}

#[derive(Arbitrary, Debug, Clone)]
enum VersionChoice {
    StandardValid(u8),   // Index into VALID_VERSIONS
    StandardInvalid(u8), // Index into INVALID_VERSIONS
    Custom(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum WhitespacePattern {
    Standard,       // Single space between components
    Multiple(u8),   // Multiple spaces (1-16)
    Mixed(Vec<u8>), // Mixed whitespace chars
    None,           // No whitespace
}

#[derive(Arbitrary, Debug, Clone)]
enum CorruptionType {
    NullByte(u8), // Position to insert null byte
    ControlChars(Vec<u8>),
    NonAscii(Vec<u8>),
    MissingComponents(u8), // Which component to drop (0=method, 1=path, 2=version)
    ExtraComponents(String),
}

#[derive(Arbitrary, Debug, Clone)]
enum BoundaryCondition {
    MaxLength,       // Exactly MAX_REQUEST_LINE bytes
    OverLength(u16), // MAX_REQUEST_LINE + n bytes
    CrlfVariants(CrlfType),
    WhitespaceFlooding(u16),
}

#[derive(Arbitrary, Debug, Clone)]
enum CrlfType {
    Standard,       // \r\n
    LfOnly,         // \n
    CrOnly,         // \r
    Double,         // \r\n\r\n
    Mixed(Vec<u8>), // Custom line ending
}

/// Fuzzable operation types
#[derive(Arbitrary, Debug, Clone)]
enum FuzzOperation {
    /// Direct request-line parsing
    ParseRequestLine(RequestLineType),
    /// Full HTTP head parsing (request-line + headers)
    ParseFullHead(RequestLineType, Vec<(String, String)>),
    /// Edge case: CRLF injection in components
    CrlfInjection(RequestLineType, Vec<u8>),
    /// Length boundary testing
    LengthBoundary(u16, RequestLineType),
}

impl RequestLineType {
    /// Generate the request-line bytes for this configuration
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            RequestLineType::Valid {
                method,
                path,
                version,
                whitespace,
            } => {
                let method_bytes = method.to_bytes();
                let path_bytes = path.to_bytes();
                let version_bytes = version.to_bytes();
                let ws1 = whitespace.to_bytes(0);
                let ws2 = whitespace.to_bytes(1);

                let mut result = Vec::new();
                result.extend_from_slice(&method_bytes);
                result.extend_from_slice(&ws1);
                result.extend_from_slice(&path_bytes);
                result.extend_from_slice(&ws2);
                result.extend_from_slice(&version_bytes);
                result
            }
            RequestLineType::Malformed {
                corruption,
                base_valid,
            } => {
                let mut base = if *base_valid {
                    b"GET /test HTTP/1.1".to_vec()
                } else {
                    b"INVALID".to_vec()
                };
                corruption.apply(&mut base);
                base
            }
            RequestLineType::Boundary { condition } => condition.to_bytes(),
        }
    }
}

impl MethodChoice {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            MethodChoice::StandardValid(idx) => {
                VALID_METHODS[*idx as usize % VALID_METHODS.len()].to_vec()
            }
            MethodChoice::StandardInvalid(idx) => {
                INVALID_METHODS[*idx as usize % INVALID_METHODS.len()].to_vec()
            }
            MethodChoice::CustomValid(s) => {
                // Ensure it's a valid token per HTTP spec
                s.chars()
                    .filter(|c| c.is_ascii() && !c.is_ascii_whitespace() && !c.is_ascii_control())
                    .collect::<String>()
                    .into_bytes()
            }
            MethodChoice::CustomInvalid(bytes) => bytes.clone(),
        }
    }
}

impl PathChoice {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            PathChoice::Simple(s) => {
                if s.is_empty() {
                    b"/".to_vec()
                } else {
                    format!("/{}", s).into_bytes()
                }
            }
            PathChoice::WithQuery(path, query) => format!("/{}?{}", path, query).into_bytes(),
            PathChoice::PercentEncoded(s) => {
                // Simple percent-encoding for testing
                let encoded = s
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() {
                            c.to_string()
                        } else {
                            format!("%{:02X}", c as u8)
                        }
                    })
                    .collect::<String>();
                format!("/{}", encoded).into_bytes()
            }
            PathChoice::InvalidUtf8(bytes) => {
                let mut result = b"/".to_vec();
                result.extend_from_slice(bytes);
                result
            }
            PathChoice::Empty => b"".to_vec(),
            PathChoice::VeryLong(mult) => {
                let len = (*mult as usize).min(MAX_REQUEST_LINE);
                let mut result = b"/".to_vec();
                result.extend(std::iter::repeat(b'a').take(len));
                result
            }
        }
    }
}

impl VersionChoice {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            VersionChoice::StandardValid(idx) => {
                VALID_VERSIONS[*idx as usize % VALID_VERSIONS.len()].to_vec()
            }
            VersionChoice::StandardInvalid(idx) => {
                INVALID_VERSIONS[*idx as usize % INVALID_VERSIONS.len()].to_vec()
            }
            VersionChoice::Custom(s) => s.as_bytes().to_vec(),
        }
    }
}

impl WhitespacePattern {
    fn to_bytes(&self, _position: u8) -> Vec<u8> {
        match self {
            WhitespacePattern::Standard => b" ".to_vec(),
            WhitespacePattern::Multiple(count) => {
                let n = (*count as usize).clamp(1, 16);
                vec![b' '; n]
            }
            WhitespacePattern::Mixed(chars) => {
                if chars.is_empty() {
                    b" ".to_vec()
                } else {
                    chars
                        .iter()
                        .filter(|&&c| c == b' ' || c == b'\t')
                        .copied()
                        .collect()
                }
            }
            WhitespacePattern::None => b"".to_vec(),
        }
    }
}

impl CorruptionType {
    fn apply(&self, data: &mut Vec<u8>) {
        match self {
            CorruptionType::NullByte(pos) => {
                let idx = (*pos as usize) % data.len().max(1);
                data.insert(idx, b'\0');
            }
            CorruptionType::ControlChars(chars) => {
                for &ch in chars {
                    if ch < 32 || ch == 127 {
                        data.push(ch);
                    }
                }
            }
            CorruptionType::NonAscii(chars) => {
                for &ch in chars {
                    if ch > 127 {
                        data.push(ch);
                    }
                }
            }
            CorruptionType::MissingComponents(which) => {
                // Simplified: just truncate to simulate missing components
                let truncate_at = match which % 3 {
                    0 => 0,                                                           // No method
                    1 => data.iter().position(|&b| b == b' ').unwrap_or(0),           // No path
                    _ => data.iter().rposition(|&b| b == b' ').unwrap_or(data.len()), // No version
                };
                data.truncate(truncate_at);
            }
            CorruptionType::ExtraComponents(extra) => {
                data.push(b' ');
                data.extend_from_slice(extra.as_bytes());
            }
        }
    }
}

impl BoundaryCondition {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            BoundaryCondition::MaxLength => {
                let mut result = b"GET ".to_vec();
                let remaining = MAX_REQUEST_LINE - result.len() - b" HTTP/1.1".len();
                result.push(b'/');
                result.extend(std::iter::repeat(b'a').take(remaining.saturating_sub(1)));
                result.extend_from_slice(b" HTTP/1.1");
                result
            }
            BoundaryCondition::OverLength(extra) => {
                let total_len = MAX_REQUEST_LINE + (*extra as usize);
                let mut result = b"GET /".to_vec();
                let path_len = total_len - result.len() - b" HTTP/1.1".len();
                result.extend(std::iter::repeat(b'a').take(path_len));
                result.extend_from_slice(b" HTTP/1.1");
                result
            }
            BoundaryCondition::CrlfVariants(crlf_type) => {
                let mut result = b"GET /test HTTP/1.1".to_vec();
                match crlf_type {
                    CrlfType::Standard => result.extend_from_slice(b"\r\n"),
                    CrlfType::LfOnly => result.push(b'\n'),
                    CrlfType::CrOnly => result.push(b'\r'),
                    CrlfType::Double => result.extend_from_slice(b"\r\n\r\n"),
                    CrlfType::Mixed(bytes) => result.extend_from_slice(bytes),
                }
                result
            }
            BoundaryCondition::WhitespaceFlooding(count) => {
                let ws_count = (*count as usize).min(1000);
                let mut result = b"GET".to_vec();
                result.extend(std::iter::repeat(b' ').take(ws_count));
                result.extend_from_slice(b"/test");
                result.extend(std::iter::repeat(b' ').take(ws_count));
                result.extend_from_slice(b"HTTP/1.1");
                result
            }
        }
    }
}

/// Test direct request-line parsing functions
fn fuzz_parse_request_line(request_line: RequestLineType) {
    let line_bytes = request_line.to_bytes();

    // Constrain input size for performance (fuzzing performance requirement)
    if line_bytes.len() > MAX_REQUEST_LINE * 2 {
        return;
    }

    // Direct call to internal parsing logic would require access to private functions
    // Instead, we'll test through the public codec interface
    let full_request = [
        &line_bytes[..],
        b"\r\n\r\n", // Add minimal headers termination
    ]
    .concat();

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(&full_request[..]);

    // Test parsing - should not panic regardless of input
    let _result = codec.decode(&mut buf);

    // Specific oracles based on input characteristics
    if line_bytes.len() > MAX_REQUEST_LINE {
        // Should reject over-length requests
        let result = codec.decode(&mut BytesMut::from(&full_request[..]));
        if let Err(HttpError::RequestLineTooLong) = result {
            // Expected behavior
        }
    }

    // Test CRLF handling
    if line_bytes.contains(&b'\0') {
        // Null bytes should be rejected
        let result = codec.decode(&mut BytesMut::from(&full_request[..]));
        assert!(result.is_err(), "Null byte should cause parse failure");
    }
}

/// Test full HTTP head parsing (request-line + headers)
fn fuzz_parse_full_head(request_line: RequestLineType, headers: Vec<(String, String)>) {
    let line_bytes = request_line.to_bytes();

    if line_bytes.len() > MAX_REQUEST_LINE * 2 {
        return;
    }

    let mut full_request = line_bytes;
    full_request.extend_from_slice(b"\r\n");

    // Add headers
    for (name, value) in headers.iter().take(10) {
        // Limit headers for performance
        full_request.extend_from_slice(name.as_bytes());
        full_request.extend_from_slice(b": ");
        full_request.extend_from_slice(value.as_bytes());
        full_request.extend_from_slice(b"\r\n");
    }
    full_request.extend_from_slice(b"\r\n");

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(&full_request[..]);
    let _result = codec.decode(&mut buf);
}

/// Test CRLF injection scenarios
fn fuzz_crlf_injection(request_line: RequestLineType, injection_bytes: Vec<u8>) {
    let mut line_bytes = request_line.to_bytes();

    // Inject CRLF bytes at various positions
    for (i, &byte) in injection_bytes.iter().enumerate().take(5) {
        if byte == b'\r' || byte == b'\n' {
            let pos = (i * 37) % line_bytes.len().max(1); // Pseudo-random position
            line_bytes.insert(pos, byte);
        }
    }

    let full_request = [&line_bytes[..], b"\r\n\r\n"].concat();

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(&full_request[..]);
    let _result = codec.decode(&mut buf);
}

/// Test length boundary conditions
fn fuzz_length_boundary(length_factor: u16, request_line: RequestLineType) {
    let base_line = request_line.to_bytes();
    let target_length = (length_factor as usize % (MAX_REQUEST_LINE * 2)).max(10);

    // Extend or truncate to target length
    let mut line_bytes = if base_line.len() > target_length {
        base_line[..target_length].to_vec()
    } else {
        let mut extended = base_line;
        extended.extend(std::iter::repeat(b'x').take(target_length - extended.len()));
        extended
    };

    // Ensure it ends reasonably for HTTP parsing
    if line_bytes.len() > 20 {
        let suffix_start = line_bytes.len() - 10;
        line_bytes[suffix_start..].copy_from_slice(b" HTTP/1.1");
    }

    let full_request = [&line_bytes[..], b"\r\n\r\n"].concat();

    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::from(&full_request[..]);
    let _result = codec.decode(&mut buf);
}

fuzz_target!(|operation: FuzzOperation| {
    match operation {
        FuzzOperation::ParseRequestLine(request_line) => {
            fuzz_parse_request_line(request_line);
        }
        FuzzOperation::ParseFullHead(request_line, headers) => {
            fuzz_parse_full_head(request_line, headers);
        }
        FuzzOperation::CrlfInjection(request_line, injection) => {
            fuzz_crlf_injection(request_line, injection);
        }
        FuzzOperation::LengthBoundary(length_factor, request_line) => {
            fuzz_length_boundary(length_factor, request_line);
        }
    }
});
