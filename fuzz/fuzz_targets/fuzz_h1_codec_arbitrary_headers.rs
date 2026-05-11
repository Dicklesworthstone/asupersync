#![no_main]

//! Focused fuzz target for HTTP/1.1 codec with arbitrary header bytes and chunked-encoding edge cases.
//!
//! This target specifically tests:
//! 1. No panics on arbitrary header byte sequences
//! 2. Malformed input returns proper HttpError (not panics)
//! 3. Chunked-encoding edge cases including malformed chunk sizes
//! 4. Header value injection via arbitrary bytes
//! 5. Transfer-Encoding parsing with malformed values
//! 6. Content-Length vs Transfer-Encoding conflicts

use arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError};

const MAX_HEADER_COUNT: usize = 16;
const MAX_HEADER_NAME_LEN: usize = 64;
const MAX_HEADER_VALUE_LEN: usize = 256;
const MAX_CHUNK_COUNT: usize = 8;
const MAX_CHUNK_SIZE: usize = 1024;

/// Fuzz input structure for arbitrary header and chunked encoding tests
#[derive(Debug)]
struct ArbitraryHeaderInput {
    /// HTTP method (kept simple for focus)
    method: &'static str,
    /// URI (kept simple for focus)
    uri: String,
    /// Arbitrary headers with potentially malformed bytes
    headers: Vec<ArbitraryHeader>,
    /// Body configuration
    body_config: BodyConfig,
    /// Maximum header size for codec configuration
    max_headers_size: u16,
}

#[derive(Debug)]
struct ArbitraryHeader {
    /// Header name with arbitrary bytes (except colon)
    name_bytes: Vec<u8>,
    /// Header value with completely arbitrary bytes
    value_bytes: Vec<u8>,
    /// Whether to inject specific attack bytes
    attack_type: HeaderAttackType,
}

#[derive(Debug, Clone, Copy)]
enum HeaderAttackType {
    Clean,
    CrlfInjection,
    NullBytes,
    HighAscii,
    MixedControl,
    LineFolding,
}

#[derive(Debug)]
enum BodyConfig {
    /// No body
    None,
    /// Content-Length body with specified size
    ContentLength(u64),
    /// Chunked encoding with arbitrary chunk data
    Chunked { chunks: Vec<ArbitraryChunk> },
    /// Both Content-Length and Transfer-Encoding (smuggling test)
    Ambiguous {
        content_length: u64,
        chunks: Vec<ArbitraryChunk>,
    },
}

#[derive(Debug)]
struct ArbitraryChunk {
    /// Size line with arbitrary bytes
    size_line_bytes: Vec<u8>,
    /// Chunk data
    data: Vec<u8>,
    /// Whether to malform this chunk
    malform: ChunkMalformType,
}

#[derive(Debug, Clone, Copy)]
enum ChunkMalformType {
    Clean,
    BadSizeLine,
    MissingSeparator,
    ExtraBytes,
    BadExtensions,
    InvalidHex,
}

impl<'a> Arbitrary<'a> for ArbitraryHeaderInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let header_count = u.int_in_range(0..=MAX_HEADER_COUNT)?;
        let mut headers = Vec::with_capacity(header_count);

        for _ in 0..header_count {
            headers.push(ArbitraryHeader::arbitrary(u)?);
        }

        // Generate simple URI
        let uri_suffix: u8 = u.arbitrary()?;
        let uri = format!("/{}", uri_suffix % 16);

        let body_config = BodyConfig::arbitrary(u)?;

        Ok(Self {
            method: match u.int_in_range(0..=2u8)? {
                0 => "GET",
                1 => "POST",
                _ => "PUT",
            },
            uri,
            headers,
            body_config,
            max_headers_size: u.int_in_range(256..=8192)?,
        })
    }
}

impl<'a> Arbitrary<'a> for ArbitraryHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let name_len = u.int_in_range(1..=MAX_HEADER_NAME_LEN)?;
        let mut name_bytes = Vec::with_capacity(name_len);
        for _ in 0..name_len {
            name_bytes.push(u.arbitrary()?);
        }

        let value_len = u.int_in_range(0..=MAX_HEADER_VALUE_LEN)?;
        let mut value_bytes = Vec::with_capacity(value_len);
        for _ in 0..value_len {
            value_bytes.push(u.arbitrary()?);
        }

        Ok(Self {
            name_bytes,
            value_bytes,
            attack_type: HeaderAttackType::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for HeaderAttackType {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(match u.int_in_range(0..=5u8)? {
            0 => Self::Clean,
            1 => Self::CrlfInjection,
            2 => Self::NullBytes,
            3 => Self::HighAscii,
            4 => Self::MixedControl,
            _ => Self::LineFolding,
        })
    }
}

impl<'a> Arbitrary<'a> for BodyConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(match u.int_in_range(0..=3u8)? {
            0 => Self::None,
            1 => Self::ContentLength(u.arbitrary::<u32>()? as u64),
            2 => {
                let chunk_count = u.int_in_range(0..=MAX_CHUNK_COUNT)?;
                let mut chunks = Vec::with_capacity(chunk_count);
                for _ in 0..chunk_count {
                    chunks.push(ArbitraryChunk::arbitrary(u)?);
                }
                Self::Chunked { chunks }
            }
            _ => {
                let chunk_count = u.int_in_range(0..=MAX_CHUNK_COUNT)?;
                let mut chunks = Vec::with_capacity(chunk_count);
                for _ in 0..chunk_count {
                    chunks.push(ArbitraryChunk::arbitrary(u)?);
                }
                Self::Ambiguous {
                    content_length: u.arbitrary::<u32>()? as u64,
                    chunks,
                }
            }
        })
    }
}

impl<'a> Arbitrary<'a> for ArbitraryChunk {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let size_line_len = u.int_in_range(1..=16)?;
        let mut size_line_bytes = Vec::with_capacity(size_line_len);
        for _ in 0..size_line_len {
            size_line_bytes.push(u.arbitrary()?);
        }

        let data_len = u.int_in_range(0..=MAX_CHUNK_SIZE)?;
        let mut data = Vec::with_capacity(data_len);
        for _ in 0..data_len {
            data.push(u.arbitrary()?);
        }

        Ok(Self {
            size_line_bytes,
            data,
            malform: ChunkMalformType::arbitrary(u)?,
        })
    }
}

impl<'a> Arbitrary<'a> for ChunkMalformType {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(match u.int_in_range(0..=5u8)? {
            0 => Self::Clean,
            1 => Self::BadSizeLine,
            2 => Self::MissingSeparator,
            3 => Self::ExtraBytes,
            4 => Self::BadExtensions,
            _ => Self::InvalidHex,
        })
    }
}

fn apply_header_attack(
    name_bytes: &[u8],
    value_bytes: &[u8],
    attack_type: HeaderAttackType,
) -> (Vec<u8>, Vec<u8>) {
    let mut name = name_bytes.to_vec();
    let mut value = value_bytes.to_vec();

    match attack_type {
        HeaderAttackType::Clean => {
            // Sanitize to valid header chars for clean test
            for b in &mut name {
                if *b == b':' || *b == b'\r' || *b == b'\n' || *b <= 32 || *b >= 127 {
                    *b = b'X';
                }
            }
            for b in &mut value {
                if *b == b'\r' || *b == b'\n' {
                    *b = b' ';
                }
            }
        }
        HeaderAttackType::CrlfInjection => {
            // Inject CRLF sequences for injection testing
            value.extend_from_slice(b"\r\nInjected: malicious\r\n");
        }
        HeaderAttackType::NullBytes => {
            // Insert null bytes
            if !name.is_empty() {
                let midpoint = name.len() / 2;
                name[midpoint] = 0;
            }
            if !value.is_empty() {
                let midpoint = value.len() / 2;
                value[midpoint] = 0;
            }
        }
        HeaderAttackType::HighAscii => {
            // Insert high ASCII/unicode bytes
            value.extend_from_slice(&[0xFF, 0xFE, 0xC0, 0x80]);
        }
        HeaderAttackType::MixedControl => {
            // Mix various control characters
            value.extend_from_slice(&[0x01, 0x02, 0x0C, 0x1F, 0x7F]);
        }
        HeaderAttackType::LineFolding => {
            // Obsolete line folding (should be rejected)
            value.extend_from_slice(b"\r\n\t continuation");
        }
    }

    (name, value)
}

fn build_http_request(input: &ArbitraryHeaderInput) -> Vec<u8> {
    let mut request = Vec::new();

    // Request line
    let request_line = format!("{} {} HTTP/1.1\r\n", input.method, input.uri);
    request.extend_from_slice(request_line.as_bytes());

    // Add a Host header for HTTP/1.1 compliance (if not overridden)
    let has_host = input.headers.iter().any(|h| {
        let (name_bytes, _) = apply_header_attack(&h.name_bytes, &h.value_bytes, h.attack_type);
        String::from_utf8_lossy(&name_bytes).eq_ignore_ascii_case("host")
    });

    if !has_host {
        request.extend_from_slice(b"Host: fuzz.test\r\n");
    }

    // Add arbitrary headers
    for header in &input.headers {
        let (name_bytes, value_bytes) =
            apply_header_attack(&header.name_bytes, &header.value_bytes, header.attack_type);

        request.extend_from_slice(&name_bytes);
        request.push(b':');
        request.push(b' ');
        request.extend_from_slice(&value_bytes);
        request.extend_from_slice(b"\r\n");
    }

    // Add body-related headers
    match &input.body_config {
        BodyConfig::None => {}
        BodyConfig::ContentLength(len) => {
            let header = format!("Content-Length: {len}\r\n");
            request.extend_from_slice(header.as_bytes());
        }
        BodyConfig::Chunked { .. } => {
            request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
        BodyConfig::Ambiguous { content_length, .. } => {
            // Potential request smuggling: both headers present
            let cl_header = format!("Content-Length: {content_length}\r\n");
            request.extend_from_slice(cl_header.as_bytes());
            request.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
        }
    }

    // End headers
    request.extend_from_slice(b"\r\n");

    // Add body content
    match &input.body_config {
        BodyConfig::None | BodyConfig::ContentLength(_) => {
            // For ContentLength, we'll add arbitrary data based on the length
            if let BodyConfig::ContentLength(len) = &input.body_config {
                let body_len = (*len as usize).min(1024); // Cap for fuzzing
                for i in 0..body_len {
                    request.push((i % 256) as u8);
                }
            }
        }
        BodyConfig::Chunked { chunks } | BodyConfig::Ambiguous { chunks, .. } => {
            for chunk in chunks {
                let size_line = apply_chunk_malformation(&chunk.size_line_bytes, chunk.malform);
                request.extend_from_slice(&size_line);
                request.extend_from_slice(b"\r\n");
                request.extend_from_slice(&chunk.data);
                request.extend_from_slice(b"\r\n");
            }
            // End chunked body
            request.extend_from_slice(b"0\r\n\r\n");
        }
    }

    request
}

fn apply_chunk_malformation(size_bytes: &[u8], malform: ChunkMalformType) -> Vec<u8> {
    match malform {
        ChunkMalformType::Clean => {
            // Generate a valid hex size
            let size = size_bytes.len() % 256;
            format!("{:x}", size).into_bytes()
        }
        ChunkMalformType::BadSizeLine => {
            // Return raw bytes that might not be valid hex
            size_bytes.to_vec()
        }
        ChunkMalformType::MissingSeparator => {
            let mut result = format!("{:x}", size_bytes.len() % 256).into_bytes();
            // Don't add proper CRLF separator - this will be added by caller
            result.extend_from_slice(b"invalid");
            result
        }
        ChunkMalformType::ExtraBytes => {
            let mut result = format!("{:x}", size_bytes.len() % 256).into_bytes();
            result.extend_from_slice(b" extra garbage");
            result
        }
        ChunkMalformType::BadExtensions => {
            let mut result = format!("{:x}", size_bytes.len() % 256).into_bytes();
            result.extend_from_slice(b";invalid=extension\x00\x01");
            result
        }
        ChunkMalformType::InvalidHex => {
            // Mix valid hex with invalid characters
            b"XYZ123".to_vec()
        }
    }
}

fn is_expected_error(err: &HttpError) -> bool {
    matches!(
        err,
        HttpError::BadRequestLine
            | HttpError::BadHeader
            | HttpError::UnsupportedVersion
            | HttpError::BadMethod
            | HttpError::BadContentLength
            | HttpError::DuplicateContentLength
            | HttpError::DuplicateTransferEncoding
            | HttpError::BadTransferEncoding
            | HttpError::InvalidHeaderName
            | HttpError::InvalidHeaderValue
            | HttpError::HeadersTooLarge
            | HttpError::TooManyHeaders
            | HttpError::RequestLineTooLong
            | HttpError::BadChunkedEncoding
            | HttpError::BodyTooLarge
            | HttpError::BodyTooLargeDetailed { .. }
            | HttpError::AmbiguousBodyLength
            | HttpError::TrailersNotAllowed
            | HttpError::PrefetchedDataRemaining(_)
            | HttpError::Io(_)
    )
}

fuzz_target!(|input: ArbitraryHeaderInput| {
    // Skip inputs that would create excessively large requests
    if input.headers.len() > MAX_HEADER_COUNT
        || input.max_headers_size < 128
        || input.max_headers_size > 16384
    {
        return;
    }

    let request_bytes = build_http_request(&input);

    // Skip excessively large requests to avoid OOM
    if request_bytes.len() > 64 * 1024 {
        return;
    }

    let mut codec = Http1Codec::new().max_headers_size(input.max_headers_size as usize);
    let mut buf = BytesMut::from(request_bytes.as_slice());

    // The core fuzzing assertion: no panics, malformed input returns Err
    match codec.decode(&mut buf) {
        Ok(Some(request)) => {
            // If parsing succeeded, verify no control characters leaked into headers
            for (name, value) in &request.headers {
                assert!(!name.contains('\0'), "null byte in header name: {name:?}");
                assert!(
                    !value.contains('\0'),
                    "null byte in header value: {value:?}"
                );
                assert!(
                    !name.contains('\r') && !name.contains('\n'),
                    "CRLF in header name: {name:?}"
                );
                assert!(
                    !value.contains('\r') && !value.contains('\n'),
                    "CRLF in header value: {value:?}"
                );
            }

            // Verify method and URI are clean
            assert!(
                !request.method.as_str().contains('\0')
                    && !request.method.as_str().contains('\r')
                    && !request.method.as_str().contains('\n'),
                "control characters in method: {:?}",
                request.method
            );

            assert!(
                !request.uri.contains('\0')
                    && !request.uri.contains('\r')
                    && !request.uri.contains('\n'),
                "control characters in URI: {:?}",
                request.uri
            );
        }
        Ok(None) => {
            // Incomplete - this is fine for fuzzing
        }
        Err(err) => {
            // Malformed input should return expected error types, not panic
            assert!(is_expected_error(&err), "unexpected error type: {err:?}");
        }
    }

    // Test eof handling if we have remaining bytes
    if !buf.is_empty() {
        match codec.decode_eof(&mut buf) {
            Ok(Some(request)) => {
                // Same validation as above
                for (name, value) in &request.headers {
                    assert!(!name.contains('\0') && !value.contains('\0'));
                    assert!(!name.contains('\r') && !name.contains('\n'));
                    assert!(!value.contains('\r') && !value.contains('\n'));
                }
            }
            Ok(None) => {}
            Err(err) => {
                assert!(is_expected_error(&err), "unexpected EOF error: {err:?}");
            }
        }
    }
});
