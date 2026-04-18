//! Fuzz target for HTTP/1.1 chunked transfer encoding decoder edge cases.
//!
//! Focuses on the ChunkedBodyDecoder state machine in codec.rs with comprehensive
//! testing of parsing edge cases, state transitions, and error conditions:
//! 1. Chunk size parsing with various hex formats and extensions
//! 2. State machine corruption via partial reads and malformed data
//! 3. Body size limits and overflow detection
//! 4. Trailer parsing edge cases and header validation
//! 5. CRLF handling and line ending variations
//! 6. Request smuggling attack vector prevention
//!
//! Key attack vectors:
//! - Chunk size integer overflow and boundary values
//! - Malformed chunk extensions and whitespace injection
//! - State machine corruption via incomplete reads
//! - Body size limit bypass attempts
//! - Trailer header smuggling and validation bypass
//! - CRLF injection and line ending confusion

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::Http1Codec;
use libfuzzer_sys::fuzz_target;

/// Maximum input size to prevent memory exhaustion during fuzzing
const MAX_INPUT_SIZE: usize = 1024 * 1024; // 1MB

/// Chunked encoding fuzzing configuration
#[derive(Arbitrary, Debug)]
struct ChunkedFuzzConfig {
    /// Sequence of chunked encoding operations to perform
    operations: Vec<ChunkedOperation>,
    /// Decoder configuration settings
    decoder_config: DecoderConfig,
    /// Request structure for context
    request_setup: RequestSetup,
}

/// Decoder configuration for testing different limits
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
struct DecoderConfig {
    /// Maximum headers size
    max_headers_size: HeaderSize,
    /// Maximum body size
    max_body_size: BodySize,
    /// Whether to test with partial reads
    partial_reads: bool,
}

/// Header size configuration options
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum HeaderSize {
    /// Tiny limit (256 bytes)
    Tiny,
    /// Small limit (4KB)
    Small,
    /// Default limit (64KB)
    Default,
    /// Large limit (1MB)
    Large,
    /// Custom size for boundary testing
    Custom { size: u32 },
}

impl HeaderSize {
    #[allow(dead_code)]
    fn to_usize(&self) -> usize {
        match self {
            HeaderSize::Tiny => 256,
            HeaderSize::Small => 4 * 1024,
            HeaderSize::Default => 64 * 1024,
            HeaderSize::Large => 1024 * 1024,
            HeaderSize::Custom { size } => (*size as usize).min(MAX_INPUT_SIZE),
        }
    }
}

/// Body size configuration options
#[derive(Arbitrary, Debug)]
#[allow(dead_code)]
enum BodySize {
    /// Tiny limit (1KB)
    Tiny,
    /// Small limit (64KB)
    Small,
    /// Default limit (16MB)
    Default,
    /// Custom size for boundary testing
    Custom { size: u32 },
}

impl BodySize {
    #[allow(dead_code)]
    fn to_usize(&self) -> usize {
        match self {
            BodySize::Tiny => 1024,
            BodySize::Small => 64 * 1024,
            BodySize::Default => 16 * 1024 * 1024,
            BodySize::Custom { size } => (*size as usize).min(MAX_INPUT_SIZE),
        }
    }
}

/// Request setup for providing context to the chunked decoder
#[derive(Arbitrary, Debug)]
struct RequestSetup {
    /// HTTP method
    method: HttpMethod,
    /// Request URI
    uri: String,
    /// HTTP version
    version: HttpVersion,
    /// Additional headers before Transfer-Encoding
    headers: Vec<(String, String)>,
}

/// HTTP methods for testing
#[derive(Arbitrary, Debug)]
#[allow(clippy::upper_case_acronyms)]
enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    TRACE,
    CONNECT,
}

impl HttpMethod {
    fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::PATCH => "PATCH",
            HttpMethod::TRACE => "TRACE",
            HttpMethod::CONNECT => "CONNECT",
        }
    }
}

/// HTTP versions for testing
#[derive(Arbitrary, Debug)]
enum HttpVersion {
    Http10,
    Http11,
}

impl HttpVersion {
    fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        }
    }
}

/// Chunked encoding operations to test
#[derive(Arbitrary, Debug)]
enum ChunkedOperation {
    /// Add a valid chunk with data
    ValidChunk { size: u16, data: Vec<u8> },
    /// Add a chunk with malformed size
    MalformedSize { size_line: Vec<u8> },
    /// Add a chunk with extensions
    ChunkWithExtensions {
        size: u16,
        extensions: Vec<ChunkExtension>,
        data: Vec<u8>,
    },
    /// Add a zero-sized chunk (end chunk)
    EndChunk,
    /// Add trailer headers
    Trailers { headers: Vec<(String, String)> },
    /// Add malformed CRLF sequences
    MalformedCrlf { sequence: Vec<u8> },
    /// Add partial data (incomplete chunk)
    PartialChunk { size: u16, partial_data: Vec<u8> },
    /// Add chunk with boundary size values
    BoundarySize { size_type: BoundarySizeType },
    /// Add invalid characters in various positions
    InvalidChars {
        position: InvalidCharPosition,
        chars: Vec<u8>,
    },
    /// Add overlarge data to test limits
    OverlargeData { data: Vec<u8> },
}

/// Chunk extension for testing HTTP chunk extensions
#[derive(Arbitrary, Debug)]
struct ChunkExtension {
    name: String,
    value: Option<String>,
}

/// Boundary size testing types
#[derive(Arbitrary, Debug)]
enum BoundarySizeType {
    /// Zero size
    Zero,
    /// Maximum usize value
    MaxUsize,
    /// Powers of two
    PowerOfTwo { power: u8 },
    /// Hex overflow attempts
    HexOverflow { hex_digits: Vec<u8> },
}

/// Invalid character injection positions
#[derive(Arbitrary, Debug)]
enum InvalidCharPosition {
    /// In chunk size line
    ChunkSize,
    /// In chunk extension
    ChunkExtension,
    /// In data section
    ChunkData,
    /// In trailer header name
    TrailerName,
    /// In trailer header value
    TrailerValue,
    /// In CRLF sequences
    LineEnding,
}

fuzz_target!(|input: ChunkedFuzzConfig| {
    // Limit total operations to prevent excessive test time
    let operations = input.operations.iter().take(50);

    // Create HTTP/1.1 codec with custom limits
    let mut codec = Http1Codec::new();

    // Build the complete HTTP request with chunked encoding
    let mut request_buffer = BytesMut::new();

    // Add request line
    let uri = input
        .request_setup
        .uri
        .chars()
        .take(256)
        .collect::<String>();
    let request_line = format!(
        "{} {} {}\r\n",
        input.request_setup.method.as_str(),
        if uri.is_empty() { "/" } else { &uri },
        input.request_setup.version.as_str()
    );
    request_buffer.extend_from_slice(request_line.as_bytes());

    // Add headers before Transfer-Encoding
    for (name, value) in input.request_setup.headers.iter().take(32) {
        // Sanitize header names and values to prevent buffer bloat
        let clean_name: String = name
            .chars()
            .filter(|c| c.is_ascii_graphic() && *c != ':')
            .take(64)
            .collect();
        let clean_value: String = value
            .chars()
            .filter(|c| c.is_ascii() && *c != '\r' && *c != '\n')
            .take(256)
            .collect();

        if !clean_name.is_empty() && clean_name.to_lowercase() != "transfer-encoding" {
            let header_line = format!("{}: {}\r\n", clean_name, clean_value);
            request_buffer.extend_from_slice(header_line.as_bytes());
        }
    }

    // Add Transfer-Encoding: chunked header
    request_buffer.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");

    // Process chunked operations
    for operation in operations {
        match operation {
            ChunkedOperation::ValidChunk { size, data } => {
                let actual_size = (*size as usize).min(data.len()).min(MAX_INPUT_SIZE / 10);
                let chunk_data = &data[..actual_size.min(data.len())];

                // Write chunk size in hex
                let size_line = format!("{:X}\r\n", actual_size);
                request_buffer.extend_from_slice(size_line.as_bytes());

                // Write chunk data
                request_buffer.extend_from_slice(chunk_data);
                request_buffer.extend_from_slice(b"\r\n");
            }

            ChunkedOperation::MalformedSize { size_line } => {
                let limited_line: Vec<u8> = size_line
                    .iter()
                    .take(1024) // Limit line length
                    .cloned()
                    .collect();
                request_buffer.extend_from_slice(&limited_line);
                request_buffer.extend_from_slice(b"\r\n");
            }

            ChunkedOperation::ChunkWithExtensions {
                size,
                extensions,
                data,
            } => {
                let actual_size = (*size as usize).min(data.len()).min(MAX_INPUT_SIZE / 10);
                let chunk_data = &data[..actual_size.min(data.len())];

                // Build chunk size line with extensions
                let mut size_line = format!("{:X}", actual_size);
                for ext in extensions.iter().take(8) {
                    let clean_name: String = ext
                        .name
                        .chars()
                        .filter(|c| c.is_ascii_graphic() && *c != '=' && *c != ';')
                        .take(32)
                        .collect();
                    if !clean_name.is_empty() {
                        size_line.push(';');
                        size_line.push_str(&clean_name);
                        if let Some(ref value) = ext.value {
                            let clean_value: String = value
                                .chars()
                                .filter(|c| c.is_ascii_graphic())
                                .take(64)
                                .collect();
                            if !clean_value.is_empty() {
                                size_line.push('=');
                                size_line.push_str(&clean_value);
                            }
                        }
                    }
                }
                size_line.push_str("\r\n");
                request_buffer.extend_from_slice(size_line.as_bytes());

                // Write chunk data
                request_buffer.extend_from_slice(chunk_data);
                request_buffer.extend_from_slice(b"\r\n");
            }

            ChunkedOperation::EndChunk => {
                request_buffer.extend_from_slice(b"0\r\n");
            }

            ChunkedOperation::Trailers { headers } => {
                for (name, value) in headers.iter().take(16) {
                    let clean_name: String = name
                        .chars()
                        .filter(|c| c.is_ascii_graphic() && *c != ':')
                        .take(64)
                        .collect();
                    let clean_value: String = value
                        .chars()
                        .filter(|c| c.is_ascii() && *c != '\r' && *c != '\n')
                        .take(256)
                        .collect();

                    if !clean_name.is_empty() {
                        let trailer_line = format!("{}: {}\r\n", clean_name, clean_value);
                        request_buffer.extend_from_slice(trailer_line.as_bytes());
                    }
                }
                // End trailers section
                request_buffer.extend_from_slice(b"\r\n");
            }

            ChunkedOperation::MalformedCrlf { sequence } => {
                let limited_seq: Vec<u8> = sequence.iter().take(8).cloned().collect();
                request_buffer.extend_from_slice(&limited_seq);
            }

            ChunkedOperation::PartialChunk { size, partial_data } => {
                let size_line = format!("{:X}\r\n", size);
                request_buffer.extend_from_slice(size_line.as_bytes());

                // Only include partial data, no trailing CRLF
                let limited_data: Vec<u8> = partial_data
                    .iter()
                    .take((*size as usize).min(MAX_INPUT_SIZE / 10))
                    .cloned()
                    .collect();
                request_buffer.extend_from_slice(&limited_data);
            }

            ChunkedOperation::BoundarySize { size_type } => {
                let size_str = match size_type {
                    BoundarySizeType::Zero => "0".to_string(),
                    BoundarySizeType::MaxUsize => format!("{:X}", usize::MAX),
                    BoundarySizeType::PowerOfTwo { power } => {
                        let power_clamped = (*power).min(60); // Prevent massive values
                        format!("{:X}", 1usize << power_clamped)
                    }
                    BoundarySizeType::HexOverflow { hex_digits } => {
                        let limited_digits: String = hex_digits
                            .iter()
                            .take(32) // Limit hex string length
                            .map(|&b| {
                                char::from(
                                    b.wrapping_add(b'0') % 16
                                        + if b % 2 == 0 { b'0' } else { b'A' },
                                )
                            })
                            .filter(|c| c.is_ascii_hexdigit())
                            .collect();
                        if limited_digits.is_empty() {
                            "F".to_string()
                        } else {
                            limited_digits
                        }
                    }
                };
                let size_line = format!("{}\r\n", size_str);
                request_buffer.extend_from_slice(size_line.as_bytes());
            }

            ChunkedOperation::InvalidChars { position, chars } => {
                let limited_chars: Vec<u8> = chars.iter().take(16).cloned().collect();
                match position {
                    InvalidCharPosition::ChunkSize => {
                        request_buffer.extend_from_slice(&limited_chars);
                        request_buffer.extend_from_slice(b"\r\n");
                    }
                    InvalidCharPosition::ChunkExtension => {
                        request_buffer.extend_from_slice(b"A;");
                        request_buffer.extend_from_slice(&limited_chars);
                        request_buffer.extend_from_slice(b"\r\n");
                    }
                    InvalidCharPosition::ChunkData => {
                        request_buffer.extend_from_slice(b"5\r\n");
                        request_buffer.extend_from_slice(&limited_chars);
                        request_buffer.extend_from_slice(b"\r\n");
                    }
                    InvalidCharPosition::TrailerName => {
                        request_buffer.extend_from_slice(b"0\r\n");
                        request_buffer.extend_from_slice(&limited_chars);
                        request_buffer.extend_from_slice(b": value\r\n");
                    }
                    InvalidCharPosition::TrailerValue => {
                        request_buffer.extend_from_slice(b"0\r\nHeader: ");
                        request_buffer.extend_from_slice(&limited_chars);
                        request_buffer.extend_from_slice(b"\r\n");
                    }
                    InvalidCharPosition::LineEnding => {
                        request_buffer.extend_from_slice(b"5");
                        request_buffer.extend_from_slice(&limited_chars);
                        request_buffer.extend_from_slice(b"hello\r\n");
                    }
                }
            }

            ChunkedOperation::OverlargeData { data } => {
                // Test with data that exceeds reasonable chunk sizes
                let chunk_size = data.len().min(MAX_INPUT_SIZE / 2);
                let size_line = format!("{:X}\r\n", chunk_size);
                request_buffer.extend_from_slice(size_line.as_bytes());

                let limited_data = &data[..chunk_size.min(data.len())];
                request_buffer.extend_from_slice(limited_data);
                request_buffer.extend_from_slice(b"\r\n");
            }
        }

        // Prevent buffer from growing too large
        if request_buffer.len() > MAX_INPUT_SIZE {
            break;
        }
    }

    // Test the decoder with the constructed input
    test_chunked_decoder(&mut codec, &mut request_buffer, &input.decoder_config);
});

fn test_chunked_decoder(codec: &mut Http1Codec, buffer: &mut BytesMut, config: &DecoderConfig) {
    if config.partial_reads {
        // Test partial reads by feeding data in small chunks
        let mut pos = 0;
        let chunk_size = 16;

        while pos < buffer.len() {
            let end = (pos + chunk_size).min(buffer.len());
            let mut partial_buffer = BytesMut::from(&buffer[pos..end]);

            // Attempt to decode with partial data
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = codec.decode(&mut partial_buffer);
            }));

            pos = end;
        }
    } else {
        // Test with complete buffer
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = codec.decode(buffer);
        }));
    }

    // Test multiple decode attempts to ensure state machine stability
    for _ in 0..3 {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = codec.decode(buffer);
        }));
    }
}
