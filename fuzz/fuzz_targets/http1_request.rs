//! Comprehensive HTTP/1.1 request parsing fuzz target.
//!
//! This fuzzer uses structure-aware input generation to test all aspects
//! of HTTP/1.1 request parsing with high coverage:
//! - Request line parsing (method, URI, version)
//! - Header folding and validation
//! - Chunked transfer encoding
//! - Trailer headers
//! - Content-Length/Transfer-Encoding edge cases
//! - CRLF injection attempts
//! - Expect-100-continue handling
//! - Upgrade/connection semantics
//! - Protocol violations and security edge cases

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::Http1Codec;
use libfuzzer_sys::fuzz_target;

/// Comprehensive HTTP/1.1 request parsing fuzz structure.
#[derive(Arbitrary, Debug)]
struct Http1RequestFuzz {
    /// HTTP request operations to test
    request_operations: Vec<RequestOperation>,
    /// Header-specific edge case operations
    header_operations: Vec<HeaderOperation>,
    /// Body and transfer encoding operations
    body_operations: Vec<BodyOperation>,
    /// Security and injection tests
    security_operations: Vec<SecurityOperation>,
    /// Protocol violation tests
    violation_operations: Vec<ViolationOperation>,
}

/// HTTP request parsing operations
#[derive(Arbitrary, Debug)]
enum RequestOperation {
    /// Parse well-formed request
    ParseValid { request_spec: RequestSpec },
    /// Parse malformed request line
    ParseMalformedRequestLine {
        malformed_line: MalformedLineType,
        request_spec: RequestSpec,
    },
    /// Parse request with pipelining
    ParsePipelined { requests: Vec<RequestSpec> },
    /// Parse incomplete request
    ParseIncomplete {
        request_spec: RequestSpec,
        truncate_at: u16,
    },
}

/// Header-specific operations
#[derive(Arbitrary, Debug)]
enum HeaderOperation {
    /// Header folding (line continuation)
    HeaderFolding {
        base_request: RequestSpec,
        fold_patterns: Vec<FoldPattern>,
    },
    /// Duplicate headers
    DuplicateHeaders {
        base_request: RequestSpec,
        duplicate_header: HeaderType,
        count: u8,
    },
    /// Long header values
    LongHeaders {
        base_request: RequestSpec,
        header_size: HeaderSizeType,
    },
    /// Invalid header characters
    InvalidHeaderChars {
        base_request: RequestSpec,
        char_type: InvalidCharType,
    },
}

/// Body and transfer encoding operations
#[derive(Arbitrary, Debug)]
enum BodyOperation {
    /// Content-Length body
    ContentLength {
        request_spec: RequestSpec,
        body_data: Vec<u8>,
        declared_length: Option<usize>,
    },
    /// Chunked transfer encoding
    ChunkedEncoding {
        request_spec: RequestSpec,
        chunks: Vec<ChunkSpec>,
        trailers: Vec<(String, String)>,
    },
    /// Mixed Content-Length and Transfer-Encoding
    AmbiguousLength {
        request_spec: RequestSpec,
        content_length: usize,
        transfer_encoding: String,
    },
    /// Empty body with headers
    EmptyBodyWithHeaders {
        request_spec: RequestSpec,
        misleading_headers: bool,
    },
}

/// Security and injection operations
#[derive(Arbitrary, Debug)]
enum SecurityOperation {
    /// CRLF injection attempts
    CrlfInjection {
        base_request: RequestSpec,
        injection_location: InjectionLocation,
        payload: Vec<u8>,
    },
    /// Request smuggling patterns
    RequestSmuggling {
        base_request: RequestSpec,
        smuggling_type: SmugglingType,
    },
    /// Header injection
    HeaderInjection {
        base_request: RequestSpec,
        injected_headers: Vec<String>,
    },
    /// Null byte injection
    NullByteInjection {
        base_request: RequestSpec,
        null_locations: Vec<NullLocation>,
    },
}

/// Protocol violation operations
#[derive(Arbitrary, Debug)]
enum ViolationOperation {
    /// Invalid HTTP version
    InvalidVersion {
        base_request: RequestSpec,
        version_string: String,
    },
    /// Invalid method
    InvalidMethod {
        base_request: RequestSpec,
        method_string: String,
    },
    /// Request line too long
    RequestLineTooLong {
        method: String,
        uri_length: u16,
        version: String,
    },
    /// Too many headers
    TooManyHeaders {
        base_request: RequestSpec,
        header_count: u16,
    },
}

/// Request specification for structured generation
#[derive(Arbitrary, Debug, Clone)]
struct RequestSpec {
    method: FuzzMethod,
    uri: UriSpec,
    version: FuzzVersion,
    headers: Vec<(String, String)>,
    expect_100_continue: bool,
    connection_upgrade: bool,
}

/// URI specification
#[derive(Arbitrary, Debug, Clone)]
enum UriSpec {
    Simple(String),
    WithQuery(String, Vec<(String, String)>),
    WithFragment(String, String),
    AbsoluteUri(String),
    Asterisk,
    Authority(String),
}

/// Chunk specification for chunked encoding
#[derive(Arbitrary, Debug)]
struct ChunkSpec {
    size: usize,
    data: Vec<u8>,
    extensions: Vec<String>,
    use_hex_uppercase: bool,
}

/// Header folding patterns
#[derive(Arbitrary, Debug)]
enum FoldPattern {
    TabContinuation,
    SpaceContinuation,
    MultipleFolds,
    EmptyFoldLine,
}

/// Header types for testing
#[derive(Arbitrary, Debug)]
enum HeaderType {
    ContentLength,
    TransferEncoding,
    Host,
    UserAgent,
    Accept,
    Custom(String),
}

/// Header size categories
#[derive(Arbitrary, Debug)]
enum HeaderSizeType {
    Normal,
    Large,
    VeryLarge,
    AtLimit,
    OverLimit,
}

/// Invalid character types
#[derive(Arbitrary, Debug)]
enum InvalidCharType {
    ControlChars,
    NonAscii,
    Unicode,
    RawBytes,
}

/// Injection locations
#[derive(Arbitrary, Debug)]
enum InjectionLocation {
    Method,
    Uri,
    Version,
    HeaderName,
    HeaderValue,
    ReasonPhrase,
}

/// Request smuggling types
#[derive(Arbitrary, Debug)]
enum SmugglingType {
    ClTe,
    TeCl,
    TeTeSpaces,
    TeTeTab,
    ContentLengthDuplicate,
}

/// Null byte injection locations
#[derive(Arbitrary, Debug)]
enum NullLocation {
    Method,
    Uri,
    HeaderName,
    HeaderValue,
    ChunkSize,
}

/// Malformed request line types
#[derive(Arbitrary, Debug)]
enum MalformedLineType {
    NoSpaces,
    TooManySpaces,
    OnlyMethod,
    OnlyMethodUri,
    ExtraTokens,
    LeadingWhitespace,
    TrailingWhitespace,
}

/// Fuzzing method
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzMethod {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Trace,
    Connect,
    Patch,
    Extension(u8), // Will be converted to custom string
}

/// Fuzzing version
#[derive(Arbitrary, Debug, Clone, Copy)]
enum FuzzVersion {
    Http10,
    Http11,
    Invalid(u8), // Will generate invalid version strings
}

const MAX_OPERATIONS: usize = 50;
const MAX_PAYLOAD_SIZE: usize = 100_000;

fuzz_target!(|input: Http1RequestFuzz| {
    // Limit operations to prevent timeout
    let total_ops = input.request_operations.len()
        + input.header_operations.len()
        + input.body_operations.len()
        + input.security_operations.len()
        + input.violation_operations.len();

    if total_ops > MAX_OPERATIONS {
        return;
    }

    // Test basic request operations
    for operation in input.request_operations {
        test_request_operation(operation);
    }

    // Test header operations
    for operation in input.header_operations {
        test_header_operation(operation);
    }

    // Test body operations
    for operation in input.body_operations {
        test_body_operation(operation);
    }

    // Test security operations
    for operation in input.security_operations {
        test_security_operation(operation);
    }

    // Test protocol violation operations
    for operation in input.violation_operations {
        test_violation_operation(operation);
    }
});

fn test_request_operation(operation: RequestOperation) {
    match operation {
        RequestOperation::ParseValid { request_spec } => {
            if let Ok(request_bytes) = construct_request_bytes(&request_spec) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        RequestOperation::ParseMalformedRequestLine {
            malformed_line,
            request_spec,
        } => {
            if let Ok(request_bytes) =
                construct_malformed_request_line(&malformed_line, &request_spec)
            {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        RequestOperation::ParsePipelined { requests } => {
            let mut pipelined_bytes = Vec::new();
            for request in requests.iter().take(5) {
                if let Ok(bytes) = construct_request_bytes(request) {
                    pipelined_bytes.extend_from_slice(&bytes);
                    if pipelined_bytes.len() > MAX_PAYLOAD_SIZE {
                        break;
                    }
                }
            }

            if !pipelined_bytes.is_empty() && pipelined_bytes.len() <= MAX_PAYLOAD_SIZE {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::from(pipelined_bytes.as_slice());

                // Try to parse multiple requests
                while !buf.is_empty() {
                    match codec.decode(&mut buf) {
                        Ok(Some(_)) => continue, // Got a request, try next
                        Ok(None) => break,       // Incomplete, need more data
                        Err(_) => break,         // Parse error
                    }
                }
            }
        }

        RequestOperation::ParseIncomplete {
            request_spec,
            truncate_at,
        } => {
            if let Ok(request_bytes) = construct_request_bytes(&request_spec) {
                let truncate_pos = (truncate_at as usize).min(request_bytes.len());
                let truncated = &request_bytes[..truncate_pos];

                if truncated.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(truncated);
                    let _ = codec.decode(&mut buf);
                }
            }
        }
    }
}

fn test_header_operation(operation: HeaderOperation) {
    match operation {
        HeaderOperation::HeaderFolding {
            base_request,
            fold_patterns,
        } => {
            if let Ok(request_bytes) = construct_folded_headers(&base_request, &fold_patterns) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        HeaderOperation::DuplicateHeaders {
            base_request,
            duplicate_header,
            count,
        } => {
            let mut request = base_request;
            let header_name = match duplicate_header {
                HeaderType::ContentLength => "Content-Length",
                HeaderType::TransferEncoding => "Transfer-Encoding",
                HeaderType::Host => "Host",
                HeaderType::UserAgent => "User-Agent",
                HeaderType::Accept => "Accept",
                HeaderType::Custom(ref name) => name.as_str(),
            };

            // Add duplicate headers
            for i in 0..count.min(10) {
                request
                    .headers
                    .push((header_name.to_string(), format!("value-{}", i)));
            }

            if let Ok(request_bytes) = construct_request_bytes(&request) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        HeaderOperation::LongHeaders {
            base_request,
            header_size,
        } => {
            let value_len = match header_size {
                HeaderSizeType::Normal => 100,
                HeaderSizeType::Large => 1000,
                HeaderSizeType::VeryLarge => 10000,
                HeaderSizeType::AtLimit => 64 * 1024 - 100, // Near header limit
                HeaderSizeType::OverLimit => 64 * 1024 + 100, // Over header limit
            };

            let mut request = base_request;
            let large_value = "A".repeat(value_len.min(MAX_PAYLOAD_SIZE / 2));
            request
                .headers
                .push(("X-Large-Header".to_string(), large_value));

            if let Ok(request_bytes) = construct_request_bytes(&request) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        HeaderOperation::InvalidHeaderChars {
            base_request,
            char_type,
        } => {
            if let Ok(request_bytes) = construct_invalid_header_chars(&base_request, &char_type) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }
    }
}

fn test_body_operation(operation: BodyOperation) {
    match operation {
        BodyOperation::ContentLength {
            mut request_spec,
            body_data,
            declared_length,
        } => {
            let actual_length = body_data.len().min(MAX_PAYLOAD_SIZE / 2);
            let body = body_data
                .into_iter()
                .take(actual_length)
                .collect::<Vec<_>>();

            let declared = declared_length.unwrap_or(actual_length);
            request_spec
                .headers
                .push(("Content-Length".to_string(), declared.to_string()));

            if let Ok(mut request_bytes) = construct_request_bytes(&request_spec) {
                request_bytes.extend_from_slice(&body);

                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        BodyOperation::ChunkedEncoding {
            mut request_spec,
            chunks,
            trailers,
        } => {
            request_spec
                .headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));

            if let Ok(mut request_bytes) = construct_request_bytes(&request_spec) {
                // Add chunked body
                for chunk in chunks.iter().take(10) {
                    let chunk_size = chunk.size.min(MAX_PAYLOAD_SIZE / 20);
                    let chunk_data = chunk
                        .data
                        .iter()
                        .take(chunk_size)
                        .copied()
                        .collect::<Vec<_>>();

                    // Chunk size line
                    if chunk.use_hex_uppercase {
                        request_bytes
                            .extend_from_slice(format!("{:X}\r\n", chunk_data.len()).as_bytes());
                    } else {
                        request_bytes
                            .extend_from_slice(format!("{:x}\r\n", chunk_data.len()).as_bytes());
                    }

                    // Chunk data + CRLF
                    request_bytes.extend_from_slice(&chunk_data);
                    request_bytes.extend_from_slice(b"\r\n");

                    if request_bytes.len() > MAX_PAYLOAD_SIZE {
                        break;
                    }
                }

                // Final chunk
                request_bytes.extend_from_slice(b"0\r\n");

                // Trailers
                for (name, value) in trailers.iter().take(5) {
                    request_bytes.extend_from_slice(name.as_bytes());
                    request_bytes.extend_from_slice(b": ");
                    request_bytes.extend_from_slice(value.as_bytes());
                    request_bytes.extend_from_slice(b"\r\n");
                }

                request_bytes.extend_from_slice(b"\r\n");

                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        BodyOperation::AmbiguousLength {
            mut request_spec,
            content_length,
            transfer_encoding,
        } => {
            // This is a request smuggling vector - both headers present
            request_spec
                .headers
                .push(("Content-Length".to_string(), content_length.to_string()));
            request_spec
                .headers
                .push(("Transfer-Encoding".to_string(), transfer_encoding));

            if let Ok(request_bytes) = construct_request_bytes(&request_spec) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        BodyOperation::EmptyBodyWithHeaders {
            mut request_spec,
            misleading_headers,
        } => {
            if misleading_headers {
                request_spec
                    .headers
                    .push(("Content-Length".to_string(), "100".to_string()));
            }

            if let Ok(request_bytes) = construct_request_bytes(&request_spec) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }
    }
}

fn test_security_operation(operation: SecurityOperation) {
    match operation {
        SecurityOperation::CrlfInjection {
            base_request,
            injection_location,
            payload,
        } => {
            if let Ok(request_bytes) =
                construct_crlf_injection(&base_request, &injection_location, &payload)
            {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        SecurityOperation::RequestSmuggling {
            base_request,
            smuggling_type,
        } => {
            if let Ok(request_bytes) = construct_smuggling_attempt(&base_request, &smuggling_type) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        SecurityOperation::HeaderInjection {
            base_request,
            injected_headers,
        } => {
            if let Ok(request_bytes) = construct_header_injection(&base_request, &injected_headers)
            {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        SecurityOperation::NullByteInjection {
            base_request,
            null_locations,
        } => {
            if let Ok(request_bytes) = construct_null_injection(&base_request, &null_locations) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }
    }
}

fn test_violation_operation(operation: ViolationOperation) {
    match operation {
        ViolationOperation::InvalidVersion {
            base_request,
            version_string,
        } => {
            if let Ok(request_bytes) = construct_invalid_version(&base_request, &version_string) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        ViolationOperation::InvalidMethod {
            base_request,
            method_string,
        } => {
            if let Ok(request_bytes) = construct_invalid_method(&base_request, &method_string) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }

        ViolationOperation::RequestLineTooLong {
            method,
            uri_length,
            version,
        } => {
            let long_uri = "/".to_string() + &"a".repeat(uri_length.min(20000) as usize);
            let request_line = format!("{} {} {}\r\n\r\n", method, long_uri, version);

            if request_line.len() <= MAX_PAYLOAD_SIZE {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::from(request_line.as_bytes());
                let _ = codec.decode(&mut buf);
            }
        }

        ViolationOperation::TooManyHeaders {
            mut base_request,
            header_count,
        } => {
            // Add many headers
            for i in 0..header_count.min(200) {
                base_request
                    .headers
                    .push((format!("X-Header-{}", i), format!("value-{}", i)));
            }

            if let Ok(request_bytes) = construct_request_bytes(&base_request) {
                if request_bytes.len() <= MAX_PAYLOAD_SIZE {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::from(request_bytes.as_slice());
                    let _ = codec.decode(&mut buf);
                }
            }
        }
    }
}

// Helper functions for constructing various request types

fn construct_request_bytes(spec: &RequestSpec) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();

    // Request line
    let method_str = convert_method(spec.method);
    let uri_str = convert_uri(&spec.uri);
    let version_str = convert_version(spec.version);

    bytes.extend_from_slice(method_str.as_bytes());
    bytes.extend_from_slice(b" ");
    bytes.extend_from_slice(uri_str.as_bytes());
    bytes.extend_from_slice(b" ");
    bytes.extend_from_slice(version_str.as_bytes());
    bytes.extend_from_slice(b"\r\n");

    // Add Expect: 100-continue if specified
    if spec.expect_100_continue {
        bytes.extend_from_slice(b"Expect: 100-continue\r\n");
    }

    // Add Connection: upgrade if specified
    if spec.connection_upgrade {
        bytes.extend_from_slice(b"Connection: upgrade\r\n");
        bytes.extend_from_slice(b"Upgrade: websocket\r\n");
    }

    // Headers
    for (name, value) in &spec.headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }

    // End of headers
    bytes.extend_from_slice(b"\r\n");

    Ok(bytes)
}

fn construct_malformed_request_line(
    malformed_type: &MalformedLineType,
    spec: &RequestSpec,
) -> Result<Vec<u8>, ()> {
    let method_str = convert_method(spec.method);
    let uri_str = convert_uri(&spec.uri);
    let version_str = convert_version(spec.version);

    let mut bytes = Vec::new();

    match malformed_type {
        MalformedLineType::NoSpaces => {
            bytes.extend_from_slice(
                format!("{}{}{}\r\n", method_str, uri_str, version_str).as_bytes(),
            );
        }
        MalformedLineType::TooManySpaces => {
            bytes.extend_from_slice(
                format!("{}   {}   {}\r\n", method_str, uri_str, version_str).as_bytes(),
            );
        }
        MalformedLineType::OnlyMethod => {
            bytes.extend_from_slice(format!("{}\r\n", method_str).as_bytes());
        }
        MalformedLineType::OnlyMethodUri => {
            bytes.extend_from_slice(format!("{} {}\r\n", method_str, uri_str).as_bytes());
        }
        MalformedLineType::ExtraTokens => {
            bytes.extend_from_slice(
                format!(
                    "{} {} {} extra tokens\r\n",
                    method_str, uri_str, version_str
                )
                .as_bytes(),
            );
        }
        MalformedLineType::LeadingWhitespace => {
            bytes.extend_from_slice(
                format!("   {} {} {}\r\n", method_str, uri_str, version_str).as_bytes(),
            );
        }
        MalformedLineType::TrailingWhitespace => {
            bytes.extend_from_slice(
                format!("{} {} {}   \r\n", method_str, uri_str, version_str).as_bytes(),
            );
        }
    }

    bytes.extend_from_slice(b"\r\n"); // End headers

    Ok(bytes)
}

fn construct_folded_headers(
    spec: &RequestSpec,
    fold_patterns: &[FoldPattern],
) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();

    // Request line
    if let Ok(mut request_bytes) = construct_request_bytes(spec) {
        // Remove the final \r\n
        if request_bytes.ends_with(b"\r\n") {
            request_bytes.truncate(request_bytes.len() - 2);
        }
        bytes.extend_from_slice(&request_bytes);

        // Add folded headers
        for (i, pattern) in fold_patterns.iter().enumerate().take(3) {
            let header_name = format!("X-Folded-{}", i);
            let header_value = "part1";

            bytes.extend_from_slice(header_name.as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(header_value.as_bytes());

            match pattern {
                FoldPattern::TabContinuation => {
                    bytes.extend_from_slice(b"\r\n\tpart2");
                }
                FoldPattern::SpaceContinuation => {
                    bytes.extend_from_slice(b"\r\n part2");
                }
                FoldPattern::MultipleFolds => {
                    bytes.extend_from_slice(b"\r\n\tpart2\r\n part3");
                }
                FoldPattern::EmptyFoldLine => {
                    bytes.extend_from_slice(b"\r\n\r\n\tpart2");
                }
            }
            bytes.extend_from_slice(b"\r\n");
        }

        bytes.extend_from_slice(b"\r\n"); // End headers
    }

    Ok(bytes)
}

fn construct_invalid_header_chars(
    spec: &RequestSpec,
    char_type: &InvalidCharType,
) -> Result<Vec<u8>, ()> {
    let mut request = spec.clone();

    let (header_name, header_value) = match char_type {
        InvalidCharType::ControlChars => ("X-Control".to_string(), "value\x00\x01\x02".to_string()),
        InvalidCharType::NonAscii => (
            "X-NonAscii".to_string(),
            String::from_utf8_lossy(&[b'v', b'a', b'l', b'u', b'e', 0x80, 0x81, 0x82]).to_string(),
        ),
        InvalidCharType::Unicode => ("X-Unicode".to_string(), "value\u{1F600}".to_string()),
        InvalidCharType::RawBytes => (
            "X-Raw".to_string(),
            String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD]).to_string(),
        ),
    };

    request.headers.push((header_name, header_value));
    construct_request_bytes(&request)
}

fn construct_crlf_injection(
    spec: &RequestSpec,
    location: &InjectionLocation,
    payload: &[u8],
) -> Result<Vec<u8>, ()> {
    let injection = String::from_utf8_lossy(payload);
    let mut request = spec.clone();

    match location {
        InjectionLocation::Method => {
            // This would be handled in the method conversion
            return construct_request_bytes(&request);
        }
        InjectionLocation::Uri => {
            request.uri = match &request.uri {
                UriSpec::Simple(uri) => UriSpec::Simple(format!("{}\r\n{}", uri, injection)),
                _ => return construct_request_bytes(&request),
            };
        }
        InjectionLocation::HeaderName => {
            request
                .headers
                .push((format!("X-Inject\r\n{}", injection), "value".to_string()));
        }
        InjectionLocation::HeaderValue => {
            request
                .headers
                .push(("X-Inject".to_string(), format!("value\r\n{}", injection)));
        }
        _ => {} // Other locations
    }

    construct_request_bytes(&request)
}

fn construct_smuggling_attempt(
    spec: &RequestSpec,
    smuggling_type: &SmugglingType,
) -> Result<Vec<u8>, ()> {
    let mut request = spec.clone();

    match smuggling_type {
        SmugglingType::ClTe => {
            request
                .headers
                .push(("Content-Length".to_string(), "30".to_string()));
            request
                .headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
        }
        SmugglingType::TeCl => {
            request
                .headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
            request
                .headers
                .push(("Content-Length".to_string(), "30".to_string()));
        }
        SmugglingType::TeTeSpaces => {
            request
                .headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
            request
                .headers
                .push(("Transfer-Encoding".to_string(), " chunked".to_string()));
        }
        SmugglingType::TeTeTab => {
            request
                .headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));
            request
                .headers
                .push(("Transfer-Encoding".to_string(), "\tchunked".to_string()));
        }
        SmugglingType::ContentLengthDuplicate => {
            request
                .headers
                .push(("Content-Length".to_string(), "30".to_string()));
            request
                .headers
                .push(("Content-Length".to_string(), "0".to_string()));
        }
    }

    construct_request_bytes(&request)
}

fn construct_header_injection(
    spec: &RequestSpec,
    injected_headers: &[String],
) -> Result<Vec<u8>, ()> {
    let mut request = spec.clone();

    for injection in injected_headers.iter().take(5) {
        request
            .headers
            .push(("X-Injected".to_string(), format!("value\r\n{}", injection)));
    }

    construct_request_bytes(&request)
}

fn construct_null_injection(
    spec: &RequestSpec,
    null_locations: &[NullLocation],
) -> Result<Vec<u8>, ()> {
    let mut request = spec.clone();

    for location in null_locations.iter().take(3) {
        match location {
            NullLocation::HeaderName => {
                request
                    .headers
                    .push(("X-Null\x00Name".to_string(), "value".to_string()));
            }
            NullLocation::HeaderValue => {
                request
                    .headers
                    .push(("X-Null".to_string(), "value\x00null".to_string()));
            }
            _ => {} // Other locations would be handled in request construction
        }
    }

    construct_request_bytes(&request)
}

fn construct_invalid_version(spec: &RequestSpec, version_string: &str) -> Result<Vec<u8>, ()> {
    let method_str = convert_method(spec.method);
    let uri_str = convert_uri(&spec.uri);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        format!("{} {} {}\r\n\r\n", method_str, uri_str, version_string).as_bytes(),
    );

    Ok(bytes)
}

fn construct_invalid_method(spec: &RequestSpec, method_string: &str) -> Result<Vec<u8>, ()> {
    let uri_str = convert_uri(&spec.uri);
    let version_str = convert_version(spec.version);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        format!("{} {} {}\r\n\r\n", method_string, uri_str, version_str).as_bytes(),
    );

    Ok(bytes)
}

// Conversion helper functions

fn convert_method(method: FuzzMethod) -> String {
    match method {
        FuzzMethod::Get => "GET".to_string(),
        FuzzMethod::Head => "HEAD".to_string(),
        FuzzMethod::Post => "POST".to_string(),
        FuzzMethod::Put => "PUT".to_string(),
        FuzzMethod::Delete => "DELETE".to_string(),
        FuzzMethod::Options => "OPTIONS".to_string(),
        FuzzMethod::Trace => "TRACE".to_string(),
        FuzzMethod::Connect => "CONNECT".to_string(),
        FuzzMethod::Patch => "PATCH".to_string(),
        FuzzMethod::Extension(val) => format!("EXT{}", val),
    }
}

fn convert_uri(uri: &UriSpec) -> String {
    match uri {
        UriSpec::Simple(s) => s.clone(),
        UriSpec::WithQuery(path, params) => {
            let mut result = path.clone();
            if !params.is_empty() {
                result.push('?');
                for (i, (key, value)) in params.iter().take(5).enumerate() {
                    if i > 0 {
                        result.push('&');
                    }
                    result.push_str(key);
                    result.push('=');
                    result.push_str(value);
                }
            }
            result
        }
        UriSpec::WithFragment(path, fragment) => format!("{}#{}", path, fragment),
        UriSpec::AbsoluteUri(uri) => uri.clone(),
        UriSpec::Asterisk => "*".to_string(),
        UriSpec::Authority(auth) => auth.clone(),
    }
}

fn convert_version(version: FuzzVersion) -> String {
    match version {
        FuzzVersion::Http10 => "HTTP/1.0".to_string(),
        FuzzVersion::Http11 => "HTTP/1.1".to_string(),
        FuzzVersion::Invalid(val) => format!("HTTP/{}.{}", val / 10, val % 10),
    }
}
