//! Fuzz target for web multipart form data parser.
//!
//! This harness tests the multipart/form-data parser with structure-aware
//! adversarial inputs including:
//! - Adversarial boundary strings (embedded, partial, missing delimiters)
//! - Nested parts with malformed boundaries
//! - Encoded headers (RFC 2047, RFC 8187 extended parameters)
//! - Oversized fields that test memory allocation limits
//! - Malformed Content-Disposition headers
//! - Invalid UTF-8 in headers and bodies
//!
//! Validates that parsing either succeeds with valid data or fails cleanly
//! without panic or unbounded allocation.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::Bytes;
use asupersync::web::extract::{ExtractionError, FromRequest, Request};
use asupersync::web::multipart::{Multipart, MultipartLimits};

const MAX_INPUT_SIZE: usize = 512 * 1024; // 512KB limit
const MAX_PARTS: usize = 50; // Limit parts to prevent excessive memory
const MAX_BOUNDARY_LEN: usize = 256; // Reasonable boundary length
const MAX_HEADER_VALUE_LEN: usize = 1024; // Limit header values

/// Adversarial multipart form configuration for structure-aware fuzzing
#[derive(Debug, Arbitrary)]
struct AdversarialMultipart {
    boundary: BoundaryConfig,
    parts: Vec<AdversarialPart>,
    preamble: Option<Vec<u8>>,
    epilogue: Option<Vec<u8>>,
    line_endings: LineEndingStyle,
    limits: LimitsConfig,
}

#[derive(Debug, Arbitrary)]
enum BoundaryConfig {
    /// Normal boundary string
    Normal { boundary: String },
    /// Boundary containing special characters
    Special {
        base: String,
        special_chars: Vec<u8>,
    },
    /// Very long boundary (test limits)
    Oversized { base: String, padding: Vec<u8> },
    /// Boundary with embedded delimiters
    Embedded { base: String, embedded: Vec<u8> },
    /// Empty or minimal boundary
    Minimal { chars: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
struct AdversarialPart {
    headers: Vec<AdversarialHeader>,
    body: BodyConfig,
    malformed: bool,
}

#[derive(Debug, Arbitrary)]
struct AdversarialHeader {
    name: HeaderName,
    value: HeaderValue,
    encoding: HeaderEncoding,
}

#[derive(Debug, Arbitrary)]
enum HeaderName {
    ContentDisposition,
    ContentType,
    Custom { name: String },
}

#[derive(Debug, Arbitrary)]
enum HeaderValue {
    /// Normal form-data value
    FormData {
        name: String,
        filename: Option<String>,
    },
    /// Malformed disposition value
    Malformed { raw: Vec<u8> },
    /// Value with special characters
    Special {
        base: String,
        special_chars: Vec<u8>,
    },
    /// Oversized value
    Oversized { base: String, padding: Vec<u8> },
    /// Empty value
    Empty,
}

#[derive(Debug, Arbitrary)]
enum HeaderEncoding {
    /// Plain ASCII
    Plain,
    /// RFC 2047 encoded words (=?charset?encoding?encoded-text?=)
    Rfc2047 {
        charset: String,
        encoding: u8,
        text: Vec<u8>,
    },
    /// RFC 8187 extended parameters (name*=charset'lang'value)
    Rfc8187 {
        charset: String,
        lang: String,
        value: Vec<u8>,
    },
    /// Invalid UTF-8
    Invalid { bytes: Vec<u8> },
}

#[derive(Debug, Arbitrary)]
enum BodyConfig {
    /// Normal text body
    Text { content: String },
    /// Binary data
    Binary { data: Vec<u8> },
    /// Oversized body
    Oversized { base: Vec<u8>, repetitions: u8 },
    /// Body containing boundary-like sequences
    BoundaryLike {
        data: Vec<u8>,
        decoy_boundary: String,
    },
    /// Empty body
    Empty,
}

#[derive(Debug, Arbitrary)]
enum LineEndingStyle {
    Crlf,  // \r\n
    Lf,    // \n
    Mixed, // Mix of both
}

#[derive(Debug, Arbitrary)]
struct LimitsConfig {
    max_total_size: Option<u16>,
    max_parts: Option<u8>,
    max_part_headers: Option<u16>,
    max_part_body_size: Option<u32>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_SIZE {
        return;
    }

    let mut u = Unstructured::new(data);
    let input: Result<AdversarialMultipart, _> = u.arbitrary();
    if input.is_err() {
        return;
    }
    let input = input.unwrap();

    test_multipart_parsing(&input);
});

/// Test multipart parsing with adversarial configurations
fn test_multipart_parsing(input: &AdversarialMultipart) {
    let boundary = build_boundary(&input.boundary);
    let multipart_body = build_multipart_body(input, &boundary);
    let limits = build_limits(&input.limits);

    if multipart_body.len() > MAX_INPUT_SIZE {
        return; // Skip excessively large inputs
    }

    // Drive the production extractor around the private multipart parser.
    test_parse_multipart_direct(&multipart_body, &boundary, &limits);

    // Test via HTTP request extraction
    test_multipart_extraction(&multipart_body, &boundary, &limits);
}

/// Test the internal parse_multipart function directly
fn test_parse_multipart_direct(body: &Bytes, boundary: &str, limits: &MultipartLimits) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parse_multipart_request(body, boundary, limits)
    }));

    match result {
        Ok(parse_result) => {
            observe_multipart_result(parse_result, limits, "direct multipart parse");
        }
        Err(_) => {
            panic!(
                "Multipart parsing panicked with input: body_len={}, boundary='{}'",
                body.len(),
                boundary
            );
        }
    }
}

/// Test multipart extraction through the HTTP request interface
fn test_multipart_extraction(body: &Bytes, boundary: &str, limits: &MultipartLimits) {
    let result = parse_multipart_request(body, boundary, limits);

    // Success and clean failure are both acceptable, but both must carry
    // useful state for the caller to act on.
    observe_multipart_result(result, limits, "multipart extraction");
}

/// Build a real request and parse it through the public multipart extractor.
fn parse_multipart_request(
    body: &Bytes,
    boundary: &str,
    limits: &MultipartLimits,
) -> Result<Multipart, ExtractionError> {
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let mut request = Request::new("POST", "/__asupersync_multipart_fuzz")
        .with_header("content-type", content_type)
        .with_body(body.clone());
    request.extensions.insert_typed(*limits);
    Multipart::from_request(request)
}

/// Validate parsed multipart invariants
fn validate_multipart_invariants(multipart: &Multipart, limits: &MultipartLimits) {
    assert!(
        multipart.len() <= limits.max_parts,
        "parsed multipart field count exceeded configured limit"
    );
    for field in multipart.fields() {
        assert!(
            field.body().len() <= limits.max_part_body_size,
            "parsed multipart field body exceeded configured limit"
        );
        assert!(
            field.headers().iter().all(|(name, value)| {
                !name.is_empty() && !value.contains('\r') && !value.contains('\n')
            }),
            "parsed multipart field headers should stay normalized"
        );
    }
}

fn validate_extraction_error(error: &ExtractionError, context: &str) {
    assert!(
        error.status.is_client_error(),
        "{context} returned non-client extraction status {}: {}",
        error.status.as_u16(),
        error.message
    );
    assert!(
        !error.message.is_empty(),
        "{context} returned empty extraction error message for status {}",
        error.status.as_u16()
    );
}

fn observe_multipart_result(
    result: Result<Multipart, ExtractionError>,
    limits: &MultipartLimits,
    context: &str,
) {
    match result {
        Ok(multipart) => validate_multipart_invariants(&multipart, limits),
        Err(error) => validate_extraction_error(&error, context),
    }
}

/// Build boundary string from configuration
fn build_boundary(config: &BoundaryConfig) -> String {
    match config {
        BoundaryConfig::Normal { boundary } => clamp_string(boundary, MAX_BOUNDARY_LEN),
        BoundaryConfig::Special {
            base,
            special_chars,
        } => {
            let mut result = clamp_string(base, MAX_BOUNDARY_LEN / 2);
            for &ch in special_chars.iter().take(MAX_BOUNDARY_LEN / 2) {
                if ch.is_ascii() && ch != b'\r' && ch != b'\n' {
                    result.push(ch as char);
                }
            }
            result
        }
        BoundaryConfig::Oversized { base, padding } => {
            let mut result = clamp_string(base, 50);
            let padding_str: String = padding
                .iter()
                .take(MAX_BOUNDARY_LEN - result.len())
                .filter(|&&b| b.is_ascii_alphanumeric())
                .map(|&b| b as char)
                .collect();
            result.push_str(&padding_str);
            result
        }
        BoundaryConfig::Embedded { base, embedded } => {
            let mut result = clamp_string(base, MAX_BOUNDARY_LEN / 2);
            result.push_str("--");
            let embedded_str: String = embedded
                .iter()
                .take(MAX_BOUNDARY_LEN - result.len())
                .filter(|&&b| b.is_ascii_alphanumeric())
                .map(|&b| b as char)
                .collect();
            result.push_str(&embedded_str);
            result
        }
        BoundaryConfig::Minimal { chars } => {
            if chars.is_empty() {
                "X".to_string()
            } else {
                chars
                    .iter()
                    .take(10)
                    .filter(|&&b| b.is_ascii_alphanumeric())
                    .map(|&b| b as char)
                    .collect::<String>()
                    .chars()
                    .take(1)
                    .chain("BOUNDARY".chars())
                    .collect()
            }
        }
    }
}

/// Build complete multipart body from configuration
fn build_multipart_body(input: &AdversarialMultipart, boundary: &str) -> Bytes {
    let mut body = Vec::new();
    let line_ending = match input.line_endings {
        LineEndingStyle::Crlf => "\r\n",
        LineEndingStyle::Lf => "\n",
        LineEndingStyle::Mixed => "\r\n", // Default to CRLF, mix later
    };

    // Add preamble if specified
    if let Some(ref preamble) = input.preamble {
        body.extend_from_slice(preamble);
        body.extend_from_slice(line_ending.as_bytes());
    }

    // Add parts (limit to prevent memory exhaustion)
    for (i, part) in input.parts.iter().take(MAX_PARTS).enumerate() {
        // Start boundary
        body.extend_from_slice(format!("--{}{}", boundary, line_ending).as_bytes());

        // Add headers
        for header in &part.headers {
            let header_line = build_header(header);
            if header_line.len() <= MAX_HEADER_VALUE_LEN {
                body.extend_from_slice(header_line.as_bytes());
                body.extend_from_slice(line_ending.as_bytes());
            }
        }

        if part.malformed {
            body.extend_from_slice(b"X-Malformed-Header-Without-Colon");
            body.extend_from_slice(line_ending.as_bytes());
        }

        // Blank line before body
        body.extend_from_slice(line_ending.as_bytes());

        // Add body
        let part_body = build_part_body(&part.body, boundary);
        body.extend_from_slice(&part_body);

        // Use different line ending occasionally for mixed mode
        if matches!(input.line_endings, LineEndingStyle::Mixed) && i % 3 == 1 {
            body.extend_from_slice("\n".as_bytes());
        } else {
            body.extend_from_slice(line_ending.as_bytes());
        }
    }

    // End boundary
    body.extend_from_slice(format!("--{}--{}", boundary, line_ending).as_bytes());

    // Add epilogue if specified
    if let Some(ref epilogue) = input.epilogue {
        body.extend_from_slice(line_ending.as_bytes());
        body.extend_from_slice(epilogue);
    }

    Bytes::from(body)
}

/// Build header string from configuration
fn build_header(header: &AdversarialHeader) -> String {
    let name = match &header.name {
        HeaderName::ContentDisposition => "Content-Disposition".to_string(),
        HeaderName::ContentType => "Content-Type".to_string(),
        HeaderName::Custom { name } => clamp_string(name, 100),
    };

    let value = build_header_value(&header.value, &header.encoding);
    format!("{}: {}", name, value)
}

/// Build header value with encoding
fn build_header_value(value: &HeaderValue, encoding: &HeaderEncoding) -> String {
    let raw_value = match value {
        HeaderValue::FormData { name, filename } => {
            let mut result = format!("form-data; name=\"{}\"", clamp_string(name, 100));
            if let Some(fname) = filename {
                result.push_str(&format!("; filename=\"{}\"", clamp_string(fname, 100)));
            }
            result
        }
        HeaderValue::Malformed { raw } => {
            String::from_utf8_lossy(&raw[..raw.len().min(MAX_HEADER_VALUE_LEN)]).to_string()
        }
        HeaderValue::Special {
            base,
            special_chars,
        } => {
            let mut result = clamp_string(base, MAX_HEADER_VALUE_LEN / 2);
            for &ch in special_chars.iter().take(MAX_HEADER_VALUE_LEN / 2) {
                if ch.is_ascii() && ch != b'\r' && ch != b'\n' {
                    result.push(ch as char);
                }
            }
            result
        }
        HeaderValue::Oversized { base, padding } => {
            let mut result = clamp_string(base, 100);
            let padding_str: String = padding
                .iter()
                .take(MAX_HEADER_VALUE_LEN - result.len())
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .map(|&b| b as char)
                .collect();
            result.push_str(&padding_str);
            result
        }
        HeaderValue::Empty => String::new(),
    };

    apply_header_encoding(&raw_value, encoding)
}

/// Apply header encoding (RFC 2047, RFC 8187, etc.)
fn apply_header_encoding(value: &str, encoding: &HeaderEncoding) -> String {
    match encoding {
        HeaderEncoding::Plain => value.to_string(),
        HeaderEncoding::Rfc2047 {
            charset,
            encoding,
            text,
        } => {
            let enc_char = match encoding % 3 {
                0 => 'Q', // Quoted-printable
                1 => 'B', // Base64
                _ => 'Q',
            };
            let text_str = String::from_utf8_lossy(&text[..text.len().min(200)]);
            format!(
                "=?{}?{}?{}?=",
                clamp_string(charset, 20),
                enc_char,
                text_str
            )
        }
        HeaderEncoding::Rfc8187 {
            charset,
            lang,
            value,
        } => {
            let value_str = String::from_utf8_lossy(&value[..value.len().min(200)]);
            format!(
                "{}*={}'{}'{}",
                "filename", // Common parameter name
                clamp_string(charset, 20),
                clamp_string(lang, 10),
                value_str
            )
        }
        HeaderEncoding::Invalid { bytes } => {
            String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_HEADER_VALUE_LEN)]).to_string()
        }
    }
}

/// Build part body from configuration
fn build_part_body(config: &BodyConfig, _boundary: &str) -> Vec<u8> {
    match config {
        BodyConfig::Text { content } => clamp_string(content, 64 * 1024).into_bytes(),
        BodyConfig::Binary { data } => data[..data.len().min(64 * 1024)].to_vec(),
        BodyConfig::Oversized { base, repetitions } => {
            let mut result = base[..base.len().min(1024)].to_vec();
            let reps = (*repetitions as usize).min(100);
            for _ in 0..reps {
                if result.len() >= 64 * 1024 {
                    break;
                }
                result.extend_from_slice(&base[..base.len().min(1024)]);
            }
            result
        }
        BodyConfig::BoundaryLike {
            data,
            decoy_boundary,
        } => {
            let mut result = data[..data.len().min(32 * 1024)].to_vec();
            result.extend_from_slice(b"--");
            result.extend_from_slice(clamp_string(decoy_boundary, 100).as_bytes());
            result.extend_from_slice(b"not-a-real-boundary");
            result
        }
        BodyConfig::Empty => Vec::new(),
    }
}

/// Build multipart limits from configuration
fn build_limits(config: &LimitsConfig) -> MultipartLimits {
    let mut limits = MultipartLimits::default();

    if let Some(size) = config.max_total_size {
        limits = limits.max_total_size((size as usize).min(1024 * 1024)); // Cap at 1MB
    }

    if let Some(parts) = config.max_parts {
        limits = limits.max_parts((parts as usize).min(100)); // Cap at 100 parts
    }

    if let Some(headers) = config.max_part_headers {
        limits = limits.max_part_headers((headers as usize).min(16 * 1024)); // Cap at 16KB
    }

    if let Some(body_size) = config.max_part_body_size {
        limits = limits.max_part_body_size((body_size as usize).min(512 * 1024)); // Cap at 512KB
    }

    limits
}

/// Utility to clamp string length
fn clamp_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s.chars().take(max_len).collect()
    }
}
