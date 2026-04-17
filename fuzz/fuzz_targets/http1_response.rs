//! Comprehensive HTTP/1.1 response encoding/decoding fuzz target.
//!
//! This fuzzer uses structure-aware input generation to test all aspects
//! of HTTP/1.1 response encoding and serialization:
//! - Status line encoding (status codes, reason phrases)
//! - Header serialization and validation
//! - Chunked transfer encoding output
//! - Trailer header encoding
//! - Content-Length validation
//! - Response body handling
//! - Edge cases and protocol compliance

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Encoder;
use asupersync::http::h1::{Http1Codec, types::Response};
use libfuzzer_sys::fuzz_target;

/// Comprehensive HTTP/1.1 response encoding fuzz structure.
#[derive(Arbitrary, Debug)]
struct Http1ResponseFuzz {
    /// Response encoding operations to test
    response_operations: Vec<ResponseOperation>,
    /// Header-specific encoding operations
    header_operations: Vec<HeaderOperation>,
    /// Body encoding operations
    body_operations: Vec<BodyOperation>,
    /// Edge case and validation operations
    validation_operations: Vec<ValidationOperation>,
}

/// HTTP response encoding operations
#[derive(Arbitrary, Debug)]
enum ResponseOperation {
    /// Encode well-formed response
    EncodeValid { response_spec: ResponseSpec },
    /// Encode response with edge case status codes
    EncodeEdgeStatus {
        status_code: u16,
        reason_phrase: String,
        response_spec: ResponseSpec,
    },
    /// Encode multiple responses in sequence
    EncodeSequence { responses: Vec<ResponseSpec> },
    /// Encode response with large body
    EncodeLargeBody {
        response_spec: ResponseSpec,
        body_size: BodySizeType,
    },
}

/// Header encoding operations
#[derive(Arbitrary, Debug)]
enum HeaderOperation {
    /// Headers with special characters
    SpecialCharHeaders {
        base_response: ResponseSpec,
        char_patterns: Vec<SpecialCharPattern>,
    },
    /// Long header values
    LongHeaders {
        base_response: ResponseSpec,
        header_length: HeaderLengthType,
    },
    /// Duplicate headers
    DuplicateHeaders {
        base_response: ResponseSpec,
        header_name: String,
        values: Vec<String>,
    },
    /// Case sensitivity tests
    CaseSensitivity {
        base_response: ResponseSpec,
        header_cases: Vec<HeaderCasePattern>,
    },
}

/// Body encoding operations
#[derive(Arbitrary, Debug)]
enum BodyOperation {
    /// Content-Length body encoding
    ContentLengthBody {
        response_spec: ResponseSpec,
        body_data: Vec<u8>,
        explicit_length: Option<usize>,
    },
    /// Chunked encoding
    ChunkedBody {
        response_spec: ResponseSpec,
        chunks: Vec<ChunkData>,
        trailers: Vec<(String, String)>,
    },
    /// Empty body with various status codes
    EmptyBody {
        status_codes: Vec<u16>,
        base_response: ResponseSpec,
    },
    /// Binary body data
    BinaryBody {
        response_spec: ResponseSpec,
        binary_data: Vec<u8>,
    },
}

/// Validation and edge case operations
#[derive(Arbitrary, Debug)]
enum ValidationOperation {
    /// Invalid header validation
    InvalidHeaders {
        base_response: ResponseSpec,
        invalid_patterns: Vec<InvalidHeaderPattern>,
    },
    /// Status code validation
    StatusCodeValidation {
        base_response: ResponseSpec,
        status_tests: Vec<StatusTest>,
    },
    /// Content-Length mismatches
    ContentLengthMismatch {
        response_spec: ResponseSpec,
        declared_length: usize,
        actual_body: Vec<u8>,
    },
    /// Trailer validation (without chunked)
    TrailerValidation {
        response_spec: ResponseSpec,
        trailers: Vec<(String, String)>,
    },
}

/// Response specification
#[derive(Arbitrary, Debug, Clone)]
struct ResponseSpec {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    version: ResponseVersion,
    use_default_reason: bool,
}

/// Chunk data for chunked encoding
#[derive(Arbitrary, Debug)]
struct ChunkData {
    data: Vec<u8>,
    size_override: Option<usize>,
    hex_format: HexFormat,
}

/// Special character patterns for headers
#[derive(Arbitrary, Debug)]
enum SpecialCharPattern {
    ControlChars,
    Unicode,
    HighAscii,
    Whitespace,
    Quotes,
    Newlines,
}

/// Header length types
#[derive(Arbitrary, Debug)]
enum HeaderLengthType {
    Short,
    Medium,
    Long,
    VeryLong,
    MaxLength,
}

/// Header case patterns
#[derive(Arbitrary, Debug)]
enum HeaderCasePattern {
    AllLowercase,
    AllUppercase,
    MixedCase,
    CamelCase,
    Random,
}

/// Body size types
#[derive(Arbitrary, Debug)]
enum BodySizeType {
    Empty,
    Small,
    Medium,
    Large,
    VeryLarge,
}

/// Invalid header patterns
#[derive(Arbitrary, Debug)]
enum InvalidHeaderPattern {
    EmptyName,
    InvalidNameChars,
    InvalidValueChars,
    CrlfInjection,
    NullBytes,
}

/// Status code test patterns
#[derive(Arbitrary, Debug)]
enum StatusTest {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
    Invalid,
}

/// Response version
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ResponseVersion {
    Http10,
    Http11,
}

/// Hex format for chunk sizes
#[derive(Arbitrary, Debug)]
enum HexFormat {
    Lowercase,
    Uppercase,
    Mixed,
}

const MAX_OPERATIONS: usize = 30;
const MAX_PAYLOAD_SIZE: usize = 100_000;

fuzz_target!(|input: Http1ResponseFuzz| {
    // Limit operations to prevent timeout
    let total_ops = input.response_operations.len()
        + input.header_operations.len()
        + input.body_operations.len()
        + input.validation_operations.len();

    if total_ops > MAX_OPERATIONS {
        return;
    }

    // Test response operations
    for operation in input.response_operations {
        test_response_operation(operation);
    }

    // Test header operations
    for operation in input.header_operations {
        test_header_operation(operation);
    }

    // Test body operations
    for operation in input.body_operations {
        test_body_operation(operation);
    }

    // Test validation operations
    for operation in input.validation_operations {
        test_validation_operation(operation);
    }
});

fn test_response_operation(operation: ResponseOperation) {
    match operation {
        ResponseOperation::EncodeValid { response_spec } => {
            if let Ok(response) = construct_response(&response_spec) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        ResponseOperation::EncodeEdgeStatus {
            status_code,
            reason_phrase,
            mut response_spec,
        } => {
            response_spec.status = status_code;
            response_spec.reason = reason_phrase;

            if let Ok(response) = construct_response(&response_spec) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        ResponseOperation::EncodeSequence { responses } => {
            let mut codec = Http1Codec::new();

            for response_spec in responses.iter().take(5) {
                if let Ok(response) = construct_response(response_spec) {
                    let mut buf = BytesMut::new();
                    let _ = codec.encode(response, &mut buf);

                    if buf.len() > MAX_PAYLOAD_SIZE {
                        break;
                    }
                }
            }
        }

        ResponseOperation::EncodeLargeBody {
            mut response_spec,
            body_size,
        } => {
            let size = match body_size {
                BodySizeType::Empty => 0,
                BodySizeType::Small => 1024,
                BodySizeType::Medium => 10_000,
                BodySizeType::Large => 50_000,
                BodySizeType::VeryLarge => 100_000,
            };

            response_spec.body = vec![b'A'; size.min(MAX_PAYLOAD_SIZE)];

            if let Ok(response) = construct_response(&response_spec) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }
    }
}

fn test_header_operation(operation: HeaderOperation) {
    match operation {
        HeaderOperation::SpecialCharHeaders {
            mut base_response,
            char_patterns,
        } => {
            for (i, pattern) in char_patterns.iter().enumerate().take(5) {
                let (name, value) = generate_special_char_header(pattern, i);
                base_response.headers.push((name, value));
            }

            if let Ok(response) = construct_response(&base_response) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        HeaderOperation::LongHeaders {
            mut base_response,
            header_length,
        } => {
            let length = match header_length {
                HeaderLengthType::Short => 50,
                HeaderLengthType::Medium => 500,
                HeaderLengthType::Long => 5000,
                HeaderLengthType::VeryLong => 50_000,
                HeaderLengthType::MaxLength => 64 * 1024,
            };

            let long_value = "A".repeat(length.min(MAX_PAYLOAD_SIZE / 2));
            base_response
                .headers
                .push(("X-Long-Header".to_string(), long_value));

            if let Ok(response) = construct_response(&base_response) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        HeaderOperation::DuplicateHeaders {
            mut base_response,
            header_name,
            values,
        } => {
            for value in values.iter().take(5) {
                base_response
                    .headers
                    .push((header_name.clone(), value.clone()));
            }

            if let Ok(response) = construct_response(&base_response) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        HeaderOperation::CaseSensitivity {
            mut base_response,
            header_cases,
        } => {
            for (i, case_pattern) in header_cases.iter().enumerate().take(5) {
                let header_name = format_header_case(&format!("X-Test-Header-{}", i), case_pattern);
                base_response
                    .headers
                    .push((header_name, format!("value-{}", i)));
            }

            if let Ok(response) = construct_response(&base_response) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }
    }
}

fn test_body_operation(operation: BodyOperation) {
    match operation {
        BodyOperation::ContentLengthBody {
            mut response_spec,
            body_data,
            explicit_length,
        } => {
            let body = body_data
                .into_iter()
                .take(MAX_PAYLOAD_SIZE / 2)
                .collect::<Vec<_>>();
            response_spec.body = body.clone();

            if let Some(length) = explicit_length {
                response_spec
                    .headers
                    .push(("Content-Length".to_string(), length.to_string()));
            }

            if let Ok(response) = construct_response(&response_spec) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        BodyOperation::ChunkedBody {
            mut response_spec,
            chunks,
            trailers,
        } => {
            response_spec
                .headers
                .push(("Transfer-Encoding".to_string(), "chunked".to_string()));

            // Build chunked body
            let mut chunked_body = Vec::new();
            for chunk in chunks.iter().take(10) {
                let chunk_data = chunk
                    .data
                    .iter()
                    .take(MAX_PAYLOAD_SIZE / 20)
                    .copied()
                    .collect::<Vec<_>>();
                chunked_body.extend_from_slice(&chunk_data);

                if chunked_body.len() > MAX_PAYLOAD_SIZE / 2 {
                    break;
                }
            }

            response_spec.body = chunked_body;

            // Add trailers to response
            for (name, value) in trailers.iter().take(3) {
                response_spec
                    .headers
                    .push((format!("Trailer-{}", name), value.clone()));
            }

            if let Ok(mut response) = construct_response(&response_spec) {
                // Add trailers to the Response struct
                for (name, value) in trailers.iter().take(3) {
                    response.trailers.push((name.clone(), value.clone()));
                }

                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        BodyOperation::EmptyBody {
            status_codes,
            mut base_response,
        } => {
            for &status in status_codes.iter().take(5) {
                base_response.status = status;
                base_response.body = Vec::new();

                if let Ok(response) = construct_response(&base_response) {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::new();
                    let _ = codec.encode(response, &mut buf);
                }
            }
        }

        BodyOperation::BinaryBody {
            mut response_spec,
            binary_data,
        } => {
            response_spec.body = binary_data.into_iter().take(MAX_PAYLOAD_SIZE / 2).collect();

            if let Ok(response) = construct_response(&response_spec) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }
    }
}

fn test_validation_operation(operation: ValidationOperation) {
    match operation {
        ValidationOperation::InvalidHeaders {
            mut base_response,
            invalid_patterns,
        } => {
            for (i, pattern) in invalid_patterns.iter().enumerate().take(3) {
                let (name, value) = generate_invalid_header(pattern, i);
                base_response.headers.push((name, value));
            }

            if let Ok(response) = construct_response(&base_response) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        ValidationOperation::StatusCodeValidation {
            mut base_response,
            status_tests,
        } => {
            for test in status_tests.iter().take(5) {
                base_response.status = match test {
                    StatusTest::Informational => 100,
                    StatusTest::Success => 200,
                    StatusTest::Redirection => 300,
                    StatusTest::ClientError => 400,
                    StatusTest::ServerError => 500,
                    StatusTest::Invalid => 999,
                };

                if let Ok(response) = construct_response(&base_response) {
                    let mut codec = Http1Codec::new();
                    let mut buf = BytesMut::new();
                    let _ = codec.encode(response, &mut buf);
                }
            }
        }

        ValidationOperation::ContentLengthMismatch {
            mut response_spec,
            declared_length,
            actual_body,
        } => {
            response_spec.body = actual_body.into_iter().take(MAX_PAYLOAD_SIZE / 2).collect();
            response_spec
                .headers
                .push(("Content-Length".to_string(), declared_length.to_string()));

            if let Ok(response) = construct_response(&response_spec) {
                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }

        ValidationOperation::TrailerValidation {
            response_spec,
            trailers,
        } => {
            // Try to add trailers without chunked encoding (should fail)
            if let Ok(mut response) = construct_response(&response_spec) {
                for (name, value) in trailers.iter().take(3) {
                    response.trailers.push((name.clone(), value.clone()));
                }

                let mut codec = Http1Codec::new();
                let mut buf = BytesMut::new();
                let _ = codec.encode(response, &mut buf);
            }
        }
    }
}

// Helper functions

fn construct_response(spec: &ResponseSpec) -> Result<Response, ()> {
    let reason = if spec.use_default_reason {
        String::new() // Will use default reason phrase
    } else {
        spec.reason.clone()
    };

    let mut response = Response::new(spec.status, &reason, spec.body.clone());

    // Set version
    response.version = match spec.version {
        ResponseVersion::Http10 => asupersync::http::h1::types::Version::Http10,
        ResponseVersion::Http11 => asupersync::http::h1::types::Version::Http11,
    };

    // Add headers
    for (name, value) in &spec.headers {
        response.headers.push((name.clone(), value.clone()));
    }

    Ok(response)
}

fn generate_special_char_header(pattern: &SpecialCharPattern, index: usize) -> (String, String) {
    let base_name = format!("X-Special-{}", index);
    match pattern {
        SpecialCharPattern::ControlChars => (base_name, "value\x01\x02\x03".to_string()),
        SpecialCharPattern::Unicode => (base_name, "value\u{1F600}\u{1F601}".to_string()),
        SpecialCharPattern::HighAscii => (
            base_name,
            String::from_utf8_lossy(&[b'v', b'a', b'l', b'u', b'e', 0x80, 0x90, 0xA0]).to_string(),
        ),
        SpecialCharPattern::Whitespace => (base_name, "value\t \r\n".to_string()),
        SpecialCharPattern::Quotes => (base_name, "value\"'`".to_string()),
        SpecialCharPattern::Newlines => (base_name, "value\r\n\nline2".to_string()),
    }
}

fn generate_invalid_header(pattern: &InvalidHeaderPattern, index: usize) -> (String, String) {
    match pattern {
        InvalidHeaderPattern::EmptyName => ("".to_string(), format!("value-{}", index)),
        InvalidHeaderPattern::InvalidNameChars => {
            ("X-Invalid\x00Name".to_string(), format!("value-{}", index))
        }
        InvalidHeaderPattern::InvalidValueChars => {
            (format!("X-Invalid-{}", index), "value\x00\x01".to_string())
        }
        InvalidHeaderPattern::CrlfInjection => (
            format!("X-Inject-{}", index),
            "value\r\nInjected: header".to_string(),
        ),
        InvalidHeaderPattern::NullBytes => {
            (format!("X-Null-{}", index), "value\x00null".to_string())
        }
    }
}

fn format_header_case(header: &str, pattern: &HeaderCasePattern) -> String {
    match pattern {
        HeaderCasePattern::AllLowercase => header.to_lowercase(),
        HeaderCasePattern::AllUppercase => header.to_uppercase(),
        HeaderCasePattern::MixedCase => header
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().to_string()
                } else {
                    c.to_lowercase().to_string()
                }
            })
            .collect(),
        HeaderCasePattern::CamelCase => header
            .split('-')
            .map(|part| {
                if part.is_empty() {
                    String::new()
                } else {
                    let mut chars = part.chars();
                    match chars.next() {
                        None => String::new(),
                        Some(first) => first
                            .to_uppercase()
                            .chain(chars.as_str().to_lowercase().chars())
                            .collect(),
                    }
                }
            })
            .collect::<Vec<_>>()
            .join("-"),
        HeaderCasePattern::Random => {
            // Simple pseudo-random case pattern
            header
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if (i * 7) % 3 == 0 {
                        c.to_uppercase().to_string()
                    } else {
                        c.to_lowercase().to_string()
                    }
                })
                .collect()
        }
    }
}
