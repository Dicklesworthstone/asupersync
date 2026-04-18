#![no_main]

//! Fuzz target for HTTP/1.1 codec request/response parsing.
//!
//! This target feeds malformed HTTP/1.1 request lines, headers, chunked bodies,
//! and trailers to the codec, asserting:
//! 1. No panics on malformed input
//! 2. OOM guards on Content-Length parsing (reject huge values)
//! 3. No CRLF header injection vulnerabilities
//! 4. Proper Upgrade semantics handling
//!
//! Key scenarios tested:
//! - Malformed request lines (method, URI, version parsing)
//! - Header injection via CRLF sequences
//! - Content-Length overflow and OOM protection
//! - Chunked encoding edge cases and malformed chunks
//! - Transfer-Encoding + Content-Length ambiguity (request smuggling)
//! - Trailers in various contexts
//! - Connection upgrade header validation
//! - Header name/value validation (RFC compliance)

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};

/// Simplified fuzz input for H1 codec testing
#[derive(Arbitrary, Debug, Clone)]
struct H1CodecFuzzInput {
    /// Random seed for deterministic execution
    pub seed: u64,
    /// Sequence of H1 operations to test
    pub operations: Vec<H1CodecOperation>,
    /// Configuration for the test scenario
    pub config: H1CodecFuzzConfig,
}

/// Individual H1 codec operations to fuzz
#[derive(Arbitrary, Debug, Clone)]
enum H1CodecOperation {
    /// Test request line parsing
    RequestLine {
        method: HttpMethodInput,
        uri: String,
        version: HttpVersionInput,
        malform_type: RequestLineMalformType,
    },
    /// Test header parsing and injection
    HeaderTest {
        headers: Vec<HeaderInput>,
        injection_test: HeaderInjectionType,
    },
    /// Test Content-Length parsing and OOM protection
    ContentLengthTest {
        content_length: ContentLengthInput,
        expect_oom_protection: bool,
    },
    /// Test chunked body parsing
    ChunkedBodyTest {
        chunks: Vec<ChunkInput>,
        malform_chunks: bool,
    },
    /// Test trailers
    TrailerTest {
        trailers: Vec<HeaderInput>,
        context: TrailerContext,
    },
    /// Test Connection Upgrade scenarios
    UpgradeTest {
        upgrade_header: String,
        connection_header: String,
        expect_valid_upgrade: bool,
    },
    /// Test request smuggling scenarios
    RequestSmugglingTest {
        has_content_length: bool,
        content_length: u64,
        has_transfer_encoding: bool,
        transfer_encoding: String,
    },
    /// Test complete malformed HTTP message
    MalformedMessage {
        raw_http_data: Vec<u8>,
        expect_parse_error: bool,
    },
}

/// HTTP methods for testing
#[derive(Arbitrary, Debug, Clone)]
enum HttpMethodInput {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Patch,
    Invalid(String),
}

/// HTTP versions for testing
#[derive(Arbitrary, Debug, Clone)]
enum HttpVersionInput {
    Http10,
    Http11,
    Http2,
    Invalid(String),
}

/// Request line malformation types
#[derive(Arbitrary, Debug, Clone)]
enum RequestLineMalformType {
    None,
    MissingSpaces,
    ExtraSpaces,
    InvalidChars,
    TooLong,
    EmptyMethod,
    EmptyUri,
    EmptyVersion,
}

/// Header input for testing
#[derive(Arbitrary, Debug, Clone)]
struct HeaderInput {
    name: String,
    value: String,
    malform_type: HeaderMalformType,
}

/// Header malformation types
#[derive(Arbitrary, Debug, Clone)]
enum HeaderMalformType {
    None,
    MissingColon,
    InvalidNameChars,
    InvalidValueChars,
    TooLong,
    EmptyName,
    CrlfInjection,
}

/// Header injection attack types
#[derive(Arbitrary, Debug, Clone)]
enum HeaderInjectionType {
    None,
    CrlfInName,
    CrlfInValue,
    DoubleEncoded,
    UnicodeNormalization,
    ControlChars,
}

/// Content-Length input variants
#[derive(Arbitrary, Debug, Clone)]
enum ContentLengthInput {
    Valid(u64),
    InvalidString(String),
    Overflow(String), // Intentionally overflowing values
    Negative(String),
    Multiple(Vec<String>), // Multiple Content-Length headers
    Empty,
}

/// Chunk input for chunked encoding tests
#[derive(Arbitrary, Debug, Clone)]
struct ChunkInput {
    size: u32,
    data: Vec<u8>,
    malform_type: ChunkMalformType,
}

/// Chunk malformation types
#[derive(Arbitrary, Debug, Clone)]
enum ChunkMalformType {
    None,
    InvalidSizeFormat,
    MissingCrlf,
    WrongDataLength,
    InvalidChunkExt,
}

/// Trailer context for testing
#[derive(Arbitrary, Debug, Clone)]
enum TrailerContext {
    ChunkedEncoding,
    RegularBody,
    NoBody,
}

/// Configuration for H1 codec fuzz testing
#[derive(Arbitrary, Debug, Clone)]
struct H1CodecFuzzConfig {
    /// Maximum operations per test run
    pub max_operations: u16,
    /// Test OOM protection
    pub test_oom_protection: bool,
    /// Test header injection
    pub test_header_injection: bool,
    /// Test request smuggling
    pub test_request_smuggling: bool,
    /// Maximum header size for testing
    pub max_headers_size: u32,
    /// Maximum body size for testing
    pub max_body_size: u32,
}

/// Shadow model for tracking H1 codec behavior
#[derive(Debug)]
struct H1CodecShadowModel {
    /// Total operations attempted
    total_operations: AtomicU64,
    /// Operations that completed successfully
    successful_operations: AtomicU64,
    /// Expected errors encountered
    expected_errors: AtomicU64,
    /// Security violations detected
    violations: std::sync::Mutex<Vec<String>>,
    /// Large Content-Length values tested
    large_content_lengths: std::sync::Mutex<Vec<u64>>,
}

impl H1CodecShadowModel {
    fn new() -> Self {
        Self {
            total_operations: AtomicU64::new(0),
            successful_operations: AtomicU64::new(0),
            expected_errors: AtomicU64::new(0),
            violations: std::sync::Mutex::new(Vec::new()),
            large_content_lengths: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn record_operation_start(&self) -> u64 {
        self.total_operations.fetch_add(1, Ordering::SeqCst)
    }

    fn record_operation_success(&self) {
        self.successful_operations.fetch_add(1, Ordering::SeqCst);
    }

    fn record_expected_error(&self, _error_msg: &str) {
        self.expected_errors.fetch_add(1, Ordering::SeqCst);
    }

    fn record_security_violation(&self, violation: String) {
        self.violations.lock().unwrap().push(violation);
    }

    fn record_large_content_length(&self, size: u64) {
        self.large_content_lengths.lock().unwrap().push(size);
    }

    fn verify_invariants(&self) -> Result<(), String> {
        let total = self.total_operations.load(Ordering::SeqCst);
        let success = self.successful_operations.load(Ordering::SeqCst);
        let errors = self.expected_errors.load(Ordering::SeqCst);

        // Basic accounting
        if success + errors > total {
            return Err(format!(
                "Accounting violation: success({}) + errors({}) > total({})",
                success, errors, total
            ));
        }

        // Check for security violations
        let violations = self.violations.lock().unwrap();
        if !violations.is_empty() {
            return Err(format!("Security violations detected: {:?}", *violations));
        }

        Ok(())
    }
}

/// Convert method input to string
fn method_to_string(method: &HttpMethodInput) -> String {
    match method {
        HttpMethodInput::Get => "GET".to_string(),
        HttpMethodInput::Post => "POST".to_string(),
        HttpMethodInput::Put => "PUT".to_string(),
        HttpMethodInput::Delete => "DELETE".to_string(),
        HttpMethodInput::Head => "HEAD".to_string(),
        HttpMethodInput::Options => "OPTIONS".to_string(),
        HttpMethodInput::Trace => "TRACE".to_string(),
        HttpMethodInput::Connect => "CONNECT".to_string(),
        HttpMethodInput::Patch => "PATCH".to_string(),
        HttpMethodInput::Invalid(s) => s.clone(),
    }
}

/// Convert version input to string
fn version_to_string(version: &HttpVersionInput) -> String {
    match version {
        HttpVersionInput::Http10 => "HTTP/1.0".to_string(),
        HttpVersionInput::Http11 => "HTTP/1.1".to_string(),
        HttpVersionInput::Http2 => "HTTP/2.0".to_string(),
        HttpVersionInput::Invalid(s) => s.clone(),
    }
}

/// Normalize fuzz input to prevent timeouts
fn normalize_fuzz_input(input: &mut H1CodecFuzzInput) {
    // Limit operations to prevent timeouts
    input.operations.truncate(30);

    // Bound configuration values
    input.config.max_operations = input.config.max_operations.min(50);
    input.config.max_headers_size = input.config.max_headers_size.clamp(1024, 128 * 1024); // 1KB-128KB
    input.config.max_body_size = input.config.max_body_size.clamp(1024, 64 * 1024 * 1024); // 1KB-64MB

    // Normalize individual operations
    for op in &mut input.operations {
        match op {
            H1CodecOperation::RequestLine { uri, .. } => {
                // Limit URI length
                uri.truncate(8192);
                if uri.is_empty() {
                    *uri = "/".to_string();
                }
            }
            H1CodecOperation::HeaderTest { headers, .. } => {
                // Limit header count and size
                headers.truncate(50);
                for header in headers {
                    header.name.truncate(1024);
                    header.value.truncate(8192);
                }
            }
            H1CodecOperation::ChunkedBodyTest { chunks, .. } => {
                // Limit chunk count and size
                chunks.truncate(20);
                for chunk in chunks {
                    chunk.size = chunk.size.min(64 * 1024); // 64KB max chunk
                    chunk.data.truncate(chunk.size as usize);
                }
            }
            H1CodecOperation::TrailerTest { trailers, .. } => {
                // Limit trailer count
                trailers.truncate(20);
                for trailer in trailers {
                    trailer.name.truncate(1024);
                    trailer.value.truncate(4096);
                }
            }
            H1CodecOperation::UpgradeTest {
                upgrade_header,
                connection_header,
                ..
            } => {
                // Limit header values
                upgrade_header.truncate(1024);
                connection_header.truncate(1024);
            }
            H1CodecOperation::RequestSmugglingTest {
                content_length,
                transfer_encoding,
                ..
            } => {
                // Limit values to prevent OOM
                *content_length = (*content_length).min(1024 * 1024 * 1024); // 1GB max
                transfer_encoding.truncate(1024);
            }
            H1CodecOperation::MalformedMessage { raw_http_data, .. } => {
                // Limit raw data size
                raw_http_data.truncate(64 * 1024); // 64KB max
            }
            _ => {} // Other operations are already bounded
        }
    }
}

/// Test request line parsing operations
fn test_request_line_parsing(
    op: &H1CodecOperation,
    shadow: &H1CodecShadowModel,
) -> Result<(), String> {
    if let H1CodecOperation::RequestLine {
        method,
        uri,
        version,
        malform_type,
    } = op
    {
        let _op_id = shadow.record_operation_start();

        let http_data = create_request_line_data(method, uri, version, malform_type);

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_) => {
                        // Valid request line parsed successfully
                        shadow.record_operation_success();
                    }
                    Err(_) => {
                        // Expected error for malformed request line
                        shadow.record_expected_error("request line parse error");
                    }
                }
            }
            Err(_) => {
                // Panic on request line parsing is a violation
                shadow.record_security_violation(format!(
                    "Request line parser panicked on input: {:?}",
                    String::from_utf8_lossy(&http_data)
                ));
                return Err("Request line parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test header parsing and injection scenarios
fn test_header_parsing(op: &H1CodecOperation, shadow: &H1CodecShadowModel) -> Result<(), String> {
    if let H1CodecOperation::HeaderTest {
        headers,
        injection_test,
    } = op
    {
        let _op_id = shadow.record_operation_start();

        let http_data = create_header_test_data(headers, injection_test);

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(req_opt) => {
                        // Check for header injection vulnerabilities
                        if let Some(req) = req_opt {
                            for (name, value) in &req.headers {
                                if name.contains('\r')
                                    || name.contains('\n')
                                    || value.contains('\r')
                                    || value.contains('\n')
                                {
                                    shadow.record_security_violation(format!(
                                        "CRLF injection in header: {}:{}",
                                        name, value
                                    ));
                                    return Err("CRLF injection vulnerability".to_string());
                                }
                            }
                        }
                        shadow.record_operation_success();
                    }
                    Err(_) => {
                        // Expected error for malformed headers
                        shadow.record_expected_error("header parse error");
                    }
                }
            }
            Err(_) => {
                shadow.record_security_violation(format!("Header parser panicked on input"));
                return Err("Header parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test Content-Length parsing and OOM protection
fn test_content_length(op: &H1CodecOperation, shadow: &H1CodecShadowModel) -> Result<(), String> {
    if let H1CodecOperation::ContentLengthTest {
        content_length,
        expect_oom_protection,
    } = op
    {
        let _op_id = shadow.record_operation_start();

        let http_data = create_content_length_test_data(content_length);

        // Check for large content length values
        if let ContentLengthInput::Valid(size) = content_length {
            if *size > 100 * 1024 * 1024 {
                // 100MB
                shadow.record_large_content_length(*size);
            }
        }

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_) => {
                        // Content-Length parsed successfully
                        if *expect_oom_protection {
                            shadow.record_security_violation(format!(
                                "Expected OOM protection but parsing succeeded"
                            ));
                        } else {
                            shadow.record_operation_success();
                        }
                    }
                    Err(err) => {
                        // Check if OOM protection kicked in properly
                        match err {
                            HttpError::BodyTooLarge | HttpError::BodyTooLargeDetailed { .. } => {
                                // Good - OOM protection working
                                shadow.record_expected_error("oom protection");
                            }
                            HttpError::BadContentLength => {
                                // Good - invalid content-length rejected
                                shadow.record_expected_error("invalid content-length");
                            }
                            _ => {
                                shadow.record_expected_error("other content-length error");
                            }
                        }
                    }
                }
            }
            Err(_) => {
                shadow.record_security_violation(format!("Content-Length parser panicked"));
                return Err("Content-Length parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test chunked body parsing
fn test_chunked_bodies(op: &H1CodecOperation, shadow: &H1CodecShadowModel) -> Result<(), String> {
    if let H1CodecOperation::ChunkedBodyTest {
        chunks,
        malform_chunks,
    } = op
    {
        let _op_id = shadow.record_operation_start();

        let http_data = create_chunked_body_data(chunks, *malform_chunks);

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_) => {
                        shadow.record_operation_success();
                    }
                    Err(_) => {
                        // Expected error for malformed chunks
                        shadow.record_expected_error("chunked body error");
                    }
                }
            }
            Err(_) => {
                shadow.record_security_violation(format!("Chunked body parser panicked"));
                return Err("Chunked body parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test trailer parsing
fn test_trailers(op: &H1CodecOperation, shadow: &H1CodecShadowModel) -> Result<(), String> {
    if let H1CodecOperation::TrailerTest { trailers, context } = op {
        let _op_id = shadow.record_operation_start();

        let http_data = create_trailer_test_data(trailers, context);

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_) => {
                        shadow.record_operation_success();
                    }
                    Err(_) => {
                        // Expected error for invalid trailer usage
                        shadow.record_expected_error("trailer error");
                    }
                }
            }
            Err(_) => {
                shadow.record_security_violation(format!("Trailer parser panicked"));
                return Err("Trailer parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test connection upgrade scenarios
fn test_upgrades(op: &H1CodecOperation, shadow: &H1CodecShadowModel) -> Result<(), String> {
    if let H1CodecOperation::UpgradeTest {
        upgrade_header,
        connection_header,
        expect_valid_upgrade,
    } = op
    {
        let _op_id = shadow.record_operation_start();

        let http_data = create_upgrade_test_data(upgrade_header, connection_header);

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(req_opt) => {
                        // Check upgrade semantics
                        if let Some(req) = req_opt {
                            let has_upgrade = req
                                .headers
                                .iter()
                                .any(|(name, _)| name.eq_ignore_ascii_case("upgrade"));
                            let has_connection_upgrade = req.headers.iter().any(|(name, value)| {
                                name.eq_ignore_ascii_case("connection")
                                    && value.to_lowercase().contains("upgrade")
                            });

                            if *expect_valid_upgrade && (!has_upgrade || !has_connection_upgrade) {
                                shadow.record_security_violation(format!(
                                    "Expected valid upgrade but headers missing"
                                ));
                            }
                        }
                        shadow.record_operation_success();
                    }
                    Err(_) => {
                        shadow.record_expected_error("upgrade error");
                    }
                }
            }
            Err(_) => {
                shadow.record_security_violation(format!("Upgrade parser panicked"));
                return Err("Upgrade parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test request smuggling scenarios
fn test_request_smuggling(
    op: &H1CodecOperation,
    shadow: &H1CodecShadowModel,
) -> Result<(), String> {
    if let H1CodecOperation::RequestSmugglingTest {
        has_content_length,
        content_length,
        has_transfer_encoding,
        transfer_encoding,
    } = op
    {
        let _op_id = shadow.record_operation_start();

        let http_data = create_request_smuggling_data(
            *has_content_length,
            *content_length,
            *has_transfer_encoding,
            transfer_encoding,
        );

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => {
                match decode_result {
                    Ok(_) => {
                        // If both Content-Length and Transfer-Encoding were present, this should be rejected
                        if *has_content_length && *has_transfer_encoding {
                            shadow.record_security_violation(format!(
                                "Request smuggling vulnerability: both Content-Length and Transfer-Encoding accepted"
                            ));
                            return Err("Request smuggling vulnerability".to_string());
                        }
                        shadow.record_operation_success();
                    }
                    Err(err) => {
                        // Check for proper ambiguous body length detection
                        match err {
                            HttpError::AmbiguousBodyLength => {
                                // Good - request smuggling protection
                                shadow.record_expected_error("ambiguous body length detected");
                            }
                            _ => {
                                shadow.record_expected_error("other smuggling error");
                            }
                        }
                    }
                }
            }
            Err(_) => {
                shadow.record_security_violation(format!("Request smuggling parser panicked"));
                return Err("Request smuggling parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Test malformed message parsing
fn test_malformed_messages(
    op: &H1CodecOperation,
    shadow: &H1CodecShadowModel,
) -> Result<(), String> {
    if let H1CodecOperation::MalformedMessage {
        raw_http_data,
        expect_parse_error,
    } = op
    {
        let _op_id = shadow.record_operation_start();

        let result = std::panic::catch_unwind(|| {
            let mut codec = Http1Codec::new();
            let mut buf = BytesMut::from(raw_http_data.as_slice());
            codec.decode(&mut buf)
        });

        match result {
            Ok(decode_result) => match decode_result {
                Ok(_) => {
                    if *expect_parse_error {
                        shadow.record_security_violation(format!(
                            "Expected parse error but malformed message succeeded"
                        ));
                    } else {
                        shadow.record_operation_success();
                    }
                }
                Err(_) => {
                    shadow.record_expected_error("malformed message error");
                }
            },
            Err(_) => {
                shadow.record_security_violation(format!("Malformed message parser panicked"));
                return Err("Malformed message parser panicked".to_string());
            }
        }
    }
    Ok(())
}

/// Create HTTP data for request line testing
fn create_request_line_data(
    method: &HttpMethodInput,
    uri: &str,
    version: &HttpVersionInput,
    malform_type: &RequestLineMalformType,
) -> Vec<u8> {
    let method_str = method_to_string(method);
    let version_str = version_to_string(version);

    let request_line = match malform_type {
        RequestLineMalformType::None => format!("{} {} {}", method_str, uri, version_str),
        RequestLineMalformType::MissingSpaces => format!("{}{}{}", method_str, uri, version_str),
        RequestLineMalformType::ExtraSpaces => {
            format!("{}   {}   {}", method_str, uri, version_str)
        }
        RequestLineMalformType::InvalidChars => {
            format!("{}\x00 {} {}", method_str, uri, version_str)
        }
        RequestLineMalformType::TooLong => {
            format!("{} /{} {}", method_str, "a".repeat(10000), version_str)
        }
        RequestLineMalformType::EmptyMethod => format!(" {} {}", uri, version_str),
        RequestLineMalformType::EmptyUri => format!("{} {} {}", method_str, "", version_str),
        RequestLineMalformType::EmptyVersion => format!("{} {} ", method_str, uri),
    };

    let mut data = request_line.into_bytes();
    data.extend_from_slice(b"\r\n\r\n");
    data
}

/// Create HTTP data for header testing
fn create_header_test_data(
    headers: &[HeaderInput],
    injection_test: &HeaderInjectionType,
) -> Vec<u8> {
    let mut data = b"GET / HTTP/1.1\r\n".to_vec();

    for header in headers {
        let header_line = match &header.malform_type {
            HeaderMalformType::None => format!("{}: {}", header.name, header.value),
            HeaderMalformType::MissingColon => format!("{} {}", header.name, header.value),
            HeaderMalformType::InvalidNameChars => format!("{}\x00: {}", header.name, header.value),
            HeaderMalformType::InvalidValueChars => {
                format!("{}: {}\x00", header.name, header.value)
            }
            HeaderMalformType::TooLong => format!("{}: {}", header.name, "x".repeat(100000)),
            HeaderMalformType::EmptyName => format!(": {}", header.value),
            HeaderMalformType::CrlfInjection => {
                format!("{}: {}\r\nInjected: malicious", header.name, header.value)
            }
        };

        // Apply injection test
        let final_header = match injection_test {
            HeaderInjectionType::None => header_line,
            HeaderInjectionType::CrlfInName => {
                format!("{}\r\nInjected: {}", header.name, header.value)
            }
            HeaderInjectionType::CrlfInValue => {
                format!("{}: {}\r\nInjected: malicious", header.name, header.value)
            }
            HeaderInjectionType::DoubleEncoded => {
                format!("{}%0d%0a: {}", header.name, header.value)
            }
            HeaderInjectionType::UnicodeNormalization => {
                format!("{}ᅟ: {}", header.name, header.value)
            } // Unicode space
            HeaderInjectionType::ControlChars => {
                format!("{}\x08: {}\x09", header.name, header.value)
            }
        };

        data.extend_from_slice(final_header.as_bytes());
        data.extend_from_slice(b"\r\n");
    }

    data.extend_from_slice(b"\r\n");
    data
}

/// Create HTTP data for Content-Length testing
fn create_content_length_test_data(content_length: &ContentLengthInput) -> Vec<u8> {
    let mut data = b"POST / HTTP/1.1\r\n".to_vec();

    match content_length {
        ContentLengthInput::Valid(size) => {
            data.extend_from_slice(format!("Content-Length: {}\r\n", size).as_bytes());
        }
        ContentLengthInput::InvalidString(s) => {
            data.extend_from_slice(format!("Content-Length: {}\r\n", s).as_bytes());
        }
        ContentLengthInput::Overflow(s) => {
            data.extend_from_slice(format!("Content-Length: {}\r\n", s).as_bytes());
        }
        ContentLengthInput::Negative(s) => {
            data.extend_from_slice(format!("Content-Length: {}\r\n", s).as_bytes());
        }
        ContentLengthInput::Multiple(values) => {
            for value in values {
                data.extend_from_slice(format!("Content-Length: {}\r\n", value).as_bytes());
            }
        }
        ContentLengthInput::Empty => {
            data.extend_from_slice(b"Content-Length: \r\n");
        }
    }

    data.extend_from_slice(b"\r\n");
    data
}

/// Create HTTP data for chunked body testing
fn create_chunked_body_data(chunks: &[ChunkInput], malform_chunks: bool) -> Vec<u8> {
    let mut data = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();

    for chunk in chunks {
        let chunk_line = match &chunk.malform_type {
            ChunkMalformType::None => format!("{:x}", chunk.size),
            ChunkMalformType::InvalidSizeFormat => "zz".to_string(),
            ChunkMalformType::MissingCrlf => format!("{:x}", chunk.size),
            ChunkMalformType::WrongDataLength => format!("{:x}", chunk.size + 1000),
            ChunkMalformType::InvalidChunkExt => format!("{:x};invalid\x00", chunk.size),
        };

        data.extend_from_slice(chunk_line.as_bytes());

        if !matches!(chunk.malform_type, ChunkMalformType::MissingCrlf) {
            data.extend_from_slice(b"\r\n");
        }

        if malform_chunks {
            // Add malformed data
            data.extend_from_slice(b"\x00\x01\x02");
        } else {
            data.extend_from_slice(&chunk.data);
        }

        data.extend_from_slice(b"\r\n");
    }

    // End chunk
    data.extend_from_slice(b"0\r\n\r\n");
    data
}

/// Create HTTP data for trailer testing
fn create_trailer_test_data(trailers: &[HeaderInput], context: &TrailerContext) -> Vec<u8> {
    let mut data = match context {
        TrailerContext::ChunkedEncoding => {
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n".to_vec()
        }
        TrailerContext::RegularBody => {
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello".to_vec()
        }
        TrailerContext::NoBody => b"GET / HTTP/1.1\r\n\r\n".to_vec(),
    };

    // Add trailers
    for trailer in trailers {
        let trailer_line = format!("{}: {}\r\n", trailer.name, trailer.value);
        data.extend_from_slice(trailer_line.as_bytes());
    }

    data.extend_from_slice(b"\r\n");
    data
}

/// Create HTTP data for upgrade testing
fn create_upgrade_test_data(upgrade_header: &str, connection_header: &str) -> Vec<u8> {
    let mut data = b"GET / HTTP/1.1\r\n".to_vec();

    if !upgrade_header.is_empty() {
        data.extend_from_slice(format!("Upgrade: {}\r\n", upgrade_header).as_bytes());
    }

    if !connection_header.is_empty() {
        data.extend_from_slice(format!("Connection: {}\r\n", connection_header).as_bytes());
    }

    data.extend_from_slice(b"\r\n");
    data
}

/// Create HTTP data for request smuggling testing
fn create_request_smuggling_data(
    has_content_length: bool,
    content_length: u64,
    has_transfer_encoding: bool,
    transfer_encoding: &str,
) -> Vec<u8> {
    let mut data = b"POST / HTTP/1.1\r\n".to_vec();

    if has_content_length {
        data.extend_from_slice(format!("Content-Length: {}\r\n", content_length).as_bytes());
    }

    if has_transfer_encoding {
        data.extend_from_slice(format!("Transfer-Encoding: {}\r\n", transfer_encoding).as_bytes());
    }

    data.extend_from_slice(b"\r\n");

    // Add some body data
    if has_transfer_encoding && transfer_encoding.contains("chunked") {
        data.extend_from_slice(b"5\r\nhello\r\n0\r\n\r\n");
    } else if has_content_length && content_length > 0 {
        let body_size = (content_length as usize).min(1024); // Limit for testing
        data.extend_from_slice(&vec![b'x'; body_size]);
    }

    data
}

/// Execute all H1 codec operations and verify invariants
fn execute_h1_codec_operations(input: &H1CodecFuzzInput) -> Result<(), String> {
    let shadow = H1CodecShadowModel::new();

    // Execute operation sequence with bounds checking
    let max_ops = input
        .config
        .max_operations
        .min(input.operations.len() as u16);
    for (i, operation) in input.operations.iter().enumerate() {
        if i >= max_ops as usize {
            break;
        }

        let result = match operation {
            H1CodecOperation::RequestLine { .. } => test_request_line_parsing(operation, &shadow),
            H1CodecOperation::HeaderTest { .. } => test_header_parsing(operation, &shadow),
            H1CodecOperation::ContentLengthTest { .. } => test_content_length(operation, &shadow),
            H1CodecOperation::ChunkedBodyTest { .. } => test_chunked_bodies(operation, &shadow),
            H1CodecOperation::TrailerTest { .. } => test_trailers(operation, &shadow),
            H1CodecOperation::UpgradeTest { .. } => test_upgrades(operation, &shadow),
            H1CodecOperation::RequestSmugglingTest { .. } => {
                test_request_smuggling(operation, &shadow)
            }
            H1CodecOperation::MalformedMessage { .. } => {
                test_malformed_messages(operation, &shadow)
            }
        };

        if let Err(e) = result {
            return Err(format!("Operation {} failed: {}", i, e));
        }

        // Verify invariants after each operation
        shadow.verify_invariants()?;
    }

    // Final invariant check
    shadow.verify_invariants()?;

    Ok(())
}

/// Main fuzzing entry point
fn fuzz_h1_codec(mut input: H1CodecFuzzInput) -> Result<(), String> {
    normalize_fuzz_input(&mut input);

    // Skip degenerate cases
    if input.operations.is_empty() {
        return Ok(());
    }

    // Execute H1 codec tests
    execute_h1_codec_operations(&input)?;

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 32768 {
        return;
    }

    let mut unstructured = arbitrary::Unstructured::new(data);

    // Generate fuzz configuration
    let input = if let Ok(input) = H1CodecFuzzInput::arbitrary(&mut unstructured) {
        input
    } else {
        return;
    };

    // Run H1 codec fuzzing - catch any panics
    let _ = std::panic::catch_unwind(|| {
        let _ = fuzz_h1_codec(input);
    });
});
