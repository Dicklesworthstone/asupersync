#![allow(warnings)]
#![allow(clippy::all)]
//! RFC 9112 Section 7: Chunked Transfer Encoding Conformance Tests
//!
//! This suite checks the production HTTP/1.1 request decoder against RFC 9112
//! §7.1 "Chunked Transfer Coding", and against the §6.1 and §6.3 framing rules
//! that decide whether a request body is chunked at all. Chunked framing is the
//! request-smuggling surface, so every verdict here comes from production code;
//! this file has no parser of its own.
//!
//! Each vector is appended to a complete request head (by default
//! `POST /p HTTP/1.1`, `Host: example`, `Transfer-Encoding: chunked`) and
//! decoded by `asupersync::http::h1::codec::Http1Codec` through
//! `Decoder::decode` twice: once with the whole input buffered, and once fed
//! one byte at a time. When the codec needs more data, `Decoder::decode_eof`
//! models the peer closing the connection. Chunk-size-line vectors also go to
//! the production line parser `fuzz_parse_chunk_size_line`. The decodes run on
//! a helper thread with a deadline, so a decoder that loops fails its case
//! instead of hanging the suite.
//!
//! ## Coverage Matrix
//!
//! | RFC Requirement | Level | Description | Decided by |
//! |----------------|-------|-------------|------------|
//! | §7.1 chunk-size | MUST | 1*HEXDIG; leading zeros are valid; `G`, `0x5` and leading whitespace are rejected | Http1Codec + fuzz_parse_chunk_size_line |
//! | §7.1 large numerals | MUST | no integer overflow or wrap; an oversized chunk is refused before buffering | Http1Codec + fuzz_parse_chunk_size_line |
//! | §7.1 chunk-data | MUST | exactly chunk-size octets, even when they contain `0\r\n\r\n` | Http1Codec |
//! | §7.1 CRLF | MUST | CRLF after the chunk-size line and after chunk-data | Http1Codec |
//! | §7.1 last-chunk | MUST | the zero-size chunk ends the body; later bytes stay unconsumed | Http1Codec |
//! | §7.1 hex case | SHOULD | `A` and `a` are the same digit | Http1Codec + fuzz_parse_chunk_size_line |
//! | §7.1.1 chunk-ext | MAY | extensions after `;` are ignored | Http1Codec + fuzz_parse_chunk_size_line |
//! | §7.1.2 trailers | MAY | trailer fields are returned apart from the body | Http1Codec |
//! | §8 incomplete | MUST | no last-chunk, truncated chunk-data or no final CRLF: never delivered | Http1Codec (decode + decode_eof) |
//! | §2.2 bare LF | MAY | a recipient may treat LF as a line end, or reject | Http1Codec |
//! | §2.2 grammar | SHOULD | a chunk-ext holding a bare LF is a grammar error (400) | Http1Codec + fuzz_parse_chunk_size_line |
//! | §6.1 TE + CL | MUST | reject, or frame by Transfer-Encoding alone; never by Content-Length | Http1Codec |
//! | §6.3 chunked not final | MUST | the request is refused before any body is framed | Http1Codec |
//! | §6.1/§6.3 400 and close | MUST | the 400 status and the connection close | not observable through Http1Codec (Skip) |

use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;
use asupersync::http::h1::codec::{Http1Codec, HttpError, fuzz_parse_chunk_size_line};
use std::sync::mpsc;
use std::time::Duration;

/// Request head that a chunked vector is appended to unless the case supplies
/// its own.
const CHUNKED_REQUEST_HEAD: &[u8] =
    b"POST /p HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n";

/// Transfer-Encoding and Content-Length together, Transfer-Encoding first.
/// Framing by Content-Length would make the body `5\r\n`.
const TE_THEN_CL_REQUEST_HEAD: &[u8] =
    b"POST /p HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n";

/// Transfer-Encoding and Content-Length together, Content-Length first.
const CL_THEN_TE_REQUEST_HEAD: &[u8] =
    b"POST /p HTTP/1.1\r\nHost: example\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";

/// Transfer-Encoding whose final coding is not chunked.
const CHUNKED_NOT_FINAL_REQUEST_HEAD: &[u8] =
    b"POST /p HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";

/// Upper bound for one case's production decodes. A decoder that never
/// returns fails the case instead of hanging the suite.
const PRODUCTION_DECODE_DEADLINE: Duration = Duration::from_secs(10);

/// The requirements that `Http1Codec` cannot show. They are reported as Skip,
/// never as Pass, and no other case may skip.
const NOT_OBSERVABLE_CASE_IDS: &[&str] = &[
    "RFC9112-6.3-chunked-not-final-400-close",
    "RFC9112-6.1-te-and-cl-close",
];

/// RFC 9112 §7 conformance test case
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ChunkedConformanceCase {
    /// Test identifier (e.g., "RFC9112-7.1.1-valid-chunk")
    id: &'static str,
    /// RFC section reference
    section: &'static str,
    /// Requirement level
    level: RequirementLevel,
    /// Human-readable description
    description: &'static str,
    /// Request head the body is appended to (normally `CHUNKED_REQUEST_HEAD`)
    head: &'static [u8],
    /// Input chunked body bytes
    input: &'static [u8],
    /// Expected parsing result
    expected: ChunkedParseResult,
    /// Trailer fields production must return, in order and nothing else
    expected_trailers: Vec<(&'static str, &'static str)>,
    /// Bytes production must leave unconsumed after the decoded request
    expected_remainder: &'static [u8],
    /// Chunk-size line for `fuzz_parse_chunk_size_line`, with the size it must
    /// return (`None`: it must fail with `HttpError::BadChunkedEncoding`)
    size_line: Option<(&'static [u8], Option<usize>)>,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
enum ChunkedParseResult {
    /// Production decodes the request with exactly these body bytes, the
    /// case's trailers and the case's unconsumed remainder.
    Success(Vec<u8>),
    /// Production rejects the chunked body: `Err(HttpError::BadChunkedEncoding)`.
    MalformedChunk,
    /// Production rejects the chunk-size: `Err(HttpError::BadChunkedEncoding)`.
    InvalidChunkSize,
    /// The zero-size last-chunk has not been received, so the message is
    /// incomplete (RFC 9112 §8). With the whole input buffered `decode` returns
    /// `Ok(None)` after consuming the head, and `decode_eof` must not produce a
    /// request.
    MissingFinalChunk,
    /// The last-chunk arrived but the chunked-body is not terminated (no final
    /// CRLF). Same incomplete verdict as `MissingFinalChunk`.
    Incomplete,
    /// The chunk size is beyond what production will buffer. It must be
    /// refused at once with a size-limit error, or with `BadChunkedEncoding`
    /// where the numeral does not fit a usize; never wrapped, never waited on.
    ChunkTooLarge,
    /// The message framing cannot be determined (RFC 9112 §6.3):
    /// `Err(HttpError::BadTransferEncoding)`.
    FramingRejected,
    /// The RFC leaves a choice: production either rejects with a framing error
    /// (`BadChunkedEncoding`, `BadTransferEncoding` or `AmbiguousBodyLength`),
    /// or decodes exactly these body bytes. Any other body is a failure.
    RejectOrDecodeAs(Vec<u8>),
    /// The requirement cannot be observed through `Http1Codec`; the text says
    /// where production implements it. Reported as Skip, never as Pass.
    NotObservable(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum RequirementLevel {
    Must,
    Should,
    May,
}

/// Test cases covering RFC 9112 §7.1 chunked encoding requirements.
#[allow(dead_code)]
fn rfc9112_chunked_cases() -> Vec<ChunkedConformanceCase> {
    vec![
        // Valid chunked encoding cases (MUST requirements)
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-simple-chunk",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "Simple chunked body with hex size and CRLF",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"5".as_slice(), Some(5))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-multiple-chunks",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "Multiple chunks concatenated",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"hello world".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"6".as_slice(), Some(6))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-zero-final-chunk",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "Final chunk MUST have size 0",
            head: CHUNKED_REQUEST_HEAD,
            input: b"3\r\nfoo\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"foo".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"0".as_slice(), Some(0))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-uppercase-hex",
            section: "7.1",
            level: RequirementLevel::Should,
            description: "Hex digits SHOULD be case insensitive",
            head: CHUNKED_REQUEST_HEAD,
            input: b"A\r\n0123456789\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"0123456789".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"A".as_slice(), Some(10))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-lowercase-hex",
            section: "7.1",
            level: RequirementLevel::Should,
            description: "Lowercase hex digits",
            head: CHUNKED_REQUEST_HEAD,
            input: b"a\r\n0123456789\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"0123456789".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"a".as_slice(), Some(10))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-chunk-extensions",
            section: "7.1.1",
            level: RequirementLevel::May,
            description: "Chunk extensions MAY be present after semicolon",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5;name=value;foo=bar\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"5;name=value;foo=bar".as_slice(), Some(5))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-trailers",
            section: "7.1.2",
            level: RequirementLevel::May,
            description: "Trailer fields MAY follow final chunk",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\nX-Checksum: abc123\r\nX-Source: test\r\n\r\n",
            expected: ChunkedParseResult::Success(b"hello".to_vec()),
            expected_trailers: vec![("X-Checksum", "abc123"), ("X-Source", "test")],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-empty-chunk",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "A zero-size chunk is the last-chunk: the bytes after its final CRLF are not body and stay unconsumed",
            head: CHUNKED_REQUEST_HEAD,
            input: b"3\r\nfoo\r\n0\r\n\r\n3\r\nbar\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"foo".to_vec()), // Only first complete message
            expected_trailers: vec![],
            expected_remainder: b"3\r\nbar\r\n0\r\n\r\n",
            size_line: None,
        },
        // Error cases (MUST reject)
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-missing-crlf-after-size",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "MUST reject chunk without CRLF after size",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\rhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::MalformedChunk,
            expected_trailers: vec![],
            expected_remainder: b"",
            // The first CRLF ends production's size line, so the line it sees
            // is "5\rhello".
            size_line: Some((b"5\rhello".as_slice(), None)),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-missing-crlf-after-data",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "MUST reject chunk without CRLF after data",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello0\r\n\r\n",
            expected: ChunkedParseResult::MalformedChunk,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-invalid-hex-chars",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "MUST reject non-hex characters in chunk size",
            head: CHUNKED_REQUEST_HEAD,
            input: b"G\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::InvalidChunkSize,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"G".as_slice(), None)),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-size-too-large",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "A chunk size larger than the buffered data leaves the message incomplete: the buffered \"0\\r\\n\\r\\n\" is chunk-data, not a last-chunk, so nothing may be delivered",
            head: CHUNKED_REQUEST_HEAD,
            input: b"10\r\nhello\r\n0\r\n\r\n", // Claims 16 bytes but only 12 follow
            expected: ChunkedParseResult::MissingFinalChunk,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"10".as_slice(), Some(16))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1.1-missing-final-chunk",
            section: "7.1, 8",
            level: RequirementLevel::Must,
            description: "Without the zero-size last-chunk the message is incomplete and MUST NOT be delivered",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\r\n",
            expected: ChunkedParseResult::MissingFinalChunk,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        // Framing precision and large numerals
        ChunkedConformanceCase {
            id: "RFC9112-7.1-chunk-size-frames-embedded-terminator",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "chunk-data is exactly chunk-size octets: a \"0\\r\\n\\r\\n\" inside the data does not end the body",
            head: CHUNKED_REQUEST_HEAD,
            input: b"10\r\nhello\r\n0\r\n\r\nABCD\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"hello\r\n0\r\n\r\nABCD".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"10".as_slice(), Some(16))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1-leading-zero-chunk-size",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "chunk-size is 1*HEXDIG: a numeral padded with 20 leading zeros is the size 5, not an overflow",
            head: CHUNKED_REQUEST_HEAD,
            input: b"000000000000000000005\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::Success(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"000000000000000000005".as_slice(), Some(5))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1-invalid-hex-0x-prefix",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "MUST reject a 0x prefix: \"x\" is not HEXDIG",
            head: CHUNKED_REQUEST_HEAD,
            input: b"0x5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::InvalidChunkSize,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"0x5".as_slice(), None)),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1-invalid-leading-whitespace-size",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "MUST reject whitespace before the chunk size: the grammar allows none there",
            head: CHUNKED_REQUEST_HEAD,
            input: b" 5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::InvalidChunkSize,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b" 5".as_slice(), None)),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1-chunk-size-overflow-wraps",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "Recipients MUST prevent integer overflow: 0x10000000000000005 does not fit a usize and must not wrap to 5",
            head: CHUNKED_REQUEST_HEAD,
            input: b"10000000000000005\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::InvalidChunkSize,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"10000000000000005".as_slice(), None)),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1-absurd-chunk-size",
            section: "7.1",
            level: RequirementLevel::Must,
            description: "A chunk of usize::MAX after 5 body bytes must not overflow the running length; production refuses it before buffering",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\r\nFFFFFFFFFFFFFFFF\r\nworld\r\n0\r\n\r\n",
            expected: ChunkedParseResult::ChunkTooLarge,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((
                b"FFFFFFFFFFFFFFFF".as_slice(),
                if cfg!(target_pointer_width = "64") {
                    Some(usize::MAX)
                } else {
                    None
                },
            )),
        },
        // Incomplete messages (RFC 9112 §8)
        ChunkedConformanceCase {
            id: "RFC9112-7.1-truncated-chunk-data",
            section: "7.1, 8",
            level: RequirementLevel::Must,
            description: "A body cut inside chunk-data is incomplete and MUST NOT be delivered",
            head: CHUNKED_REQUEST_HEAD,
            input: b"a\r\nhello",
            expected: ChunkedParseResult::MissingFinalChunk,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"a".as_slice(), Some(10))),
        },
        ChunkedConformanceCase {
            id: "RFC9112-7.1-missing-final-crlf",
            section: "7.1, 8",
            level: RequirementLevel::Must,
            description: "A last-chunk without the final CRLF is an incomplete chunked-body and MUST NOT be delivered",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\n",
            expected: ChunkedParseResult::Incomplete,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        // Bare LF line ends (RFC 9112 §2.2: a recipient MAY recognise LF)
        ChunkedConformanceCase {
            id: "RFC9112-2.2-bare-lf-after-size",
            section: "2.2, 7.1",
            level: RequirementLevel::May,
            description: "Bare LF after the chunk size: production may recognise it as a line end or reject; any other body fails",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::RejectOrDecodeAs(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-2.2-bare-lf-after-data",
            section: "2.2, 7.1",
            level: RequirementLevel::May,
            description: "Bare LF after chunk-data: production may recognise it as a line end or reject; any other body fails",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\n0\r\n\r\n",
            expected: ChunkedParseResult::RejectOrDecodeAs(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-2.2-bare-lf-last-chunk",
            section: "2.2, 7.1",
            level: RequirementLevel::May,
            description: "Bare LF after the last-chunk size: production may recognise it as a line end or reject; any other body fails",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\n\r\n",
            expected: ChunkedParseResult::RejectOrDecodeAs(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-2.2-bare-lf-in-chunk-ext",
            section: "2.2, 7.1.1",
            level: RequirementLevel::Should,
            description: "A chunk-ext holding a bare LF matches no grammar; the server SHOULD answer 400. A peer that ends the line at the LF frames the body differently",
            head: CHUNKED_REQUEST_HEAD,
            input: b"5;ext\nX\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::MalformedChunk,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: Some((b"5;ext\nX".as_slice(), None)),
        },
        // Which framing applies (RFC 9112 §6.1, §6.3)
        ChunkedConformanceCase {
            id: "RFC9112-6.1-te-and-cl",
            section: "6.1, 6.3",
            level: RequirementLevel::Must,
            description: "Transfer-Encoding with Content-Length: reject, or frame by Transfer-Encoding alone; never by Content-Length",
            head: TE_THEN_CL_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::RejectOrDecodeAs(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-6.1-cl-and-te",
            section: "6.1, 6.3",
            level: RequirementLevel::Must,
            description: "Content-Length before Transfer-Encoding: same verdict as the other header order",
            head: CL_THEN_TE_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::RejectOrDecodeAs(b"hello".to_vec()),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-6.3-chunked-not-final",
            section: "6.3",
            level: RequirementLevel::Must,
            description: "A request whose final transfer coding is not chunked has no reliable length: refused before any body is framed",
            head: CHUNKED_NOT_FINAL_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::FramingRejected,
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-6.3-chunked-not-final-400-close",
            section: "6.3",
            level: RequirementLevel::Must,
            description: "For that request the server MUST respond 400 and then close the connection",
            head: CHUNKED_NOT_FINAL_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::NotObservable(
                "Http1Codec only returns Err(BadTransferEncoding); the 400 with Connection: close is written by the server loop (src/http/h1/server.rs, private fn head_parse_failure_response), which this module does not drive",
            ),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
        ChunkedConformanceCase {
            id: "RFC9112-6.1-te-and-cl-close",
            section: "6.1, 6.3",
            level: RequirementLevel::Must,
            description: "After responding to a request with both Transfer-Encoding and Content-Length the server MUST close the connection",
            head: TE_THEN_CL_REQUEST_HEAD,
            input: b"5\r\nhello\r\n0\r\n\r\n",
            expected: ChunkedParseResult::NotObservable(
                "Http1Codec only returns Err(AmbiguousBodyLength); the response and connection close are the server loop's (src/http/h1/server.rs, private fn head_parse_failure_response), which this module does not drive",
            ),
            expected_trailers: vec![],
            expected_remainder: b"",
            size_line: None,
        },
    ]
}

/// What `Decoder::decode_eof` did once the codec had asked for more data.
#[derive(Debug)]
#[allow(dead_code)]
enum EofOutcome {
    /// `Ok(None)`: production reported a clean end of stream.
    CleanEof,
    /// `Ok(Some(request))`: production delivered a request at end of stream.
    Delivered { body: Vec<u8> },
    /// `Err(error)`.
    Rejected(HttpError),
}

/// What `Http1Codec` did with one request.
#[derive(Debug)]
#[allow(dead_code)]
enum ProductionOutcome {
    /// `decode` returned a request.
    Decoded {
        body: Vec<u8>,
        trailers: Vec<(String, String)>,
        /// Bytes left in the buffer after the request.
        remainder: Vec<u8>,
    },
    /// `decode` returned `Ok(None)` with the whole input buffered.
    NeedsMoreData {
        /// Bytes still buffered after the last `decode`.
        buffered: usize,
        /// What `decode_eof` returned next.
        at_eof: EofOutcome,
    },
    /// `decode` returned an error.
    Rejected(HttpError),
}

/// Production results for one case.
#[derive(Debug)]
#[allow(dead_code)]
struct ProductionProbe {
    /// The whole request buffered before the first `decode`.
    whole: ProductionOutcome,
    /// The request appended one byte at a time, with `decode` after each.
    byte_at_a_time: ProductionOutcome,
    /// `fuzz_parse_chunk_size_line` on the case's size line, if it has one.
    size_line: Option<Result<usize, HttpError>>,
}

#[allow(dead_code)]
fn request_bytes(case: &ChunkedConformanceCase) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(case.head.len() + case.input.len());
    bytes.extend_from_slice(case.head);
    bytes.extend_from_slice(case.input);
    bytes
}

/// The codec asked for more data with everything already buffered: model the
/// peer closing the connection.
#[allow(dead_code)]
fn finish_at_eof(codec: &mut Http1Codec, src: &mut BytesMut) -> ProductionOutcome {
    let buffered = src.len();
    let at_eof = match codec.decode_eof(src) {
        Ok(None) => EofOutcome::CleanEof,
        Ok(Some(decoded)) => EofOutcome::Delivered { body: decoded.body },
        Err(error) => EofOutcome::Rejected(error),
    };
    ProductionOutcome::NeedsMoreData { buffered, at_eof }
}

#[allow(dead_code)]
fn decode_whole(request: &[u8]) -> ProductionOutcome {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::from(request);
    match codec.decode(&mut src) {
        Ok(Some(decoded)) => {
            let remainder: &[u8] = src.as_ref();
            ProductionOutcome::Decoded {
                body: decoded.body,
                trailers: decoded.trailers,
                remainder: remainder.to_vec(),
            }
        }
        Ok(None) => finish_at_eof(&mut codec, &mut src),
        Err(error) => ProductionOutcome::Rejected(error),
    }
}

/// Segment boundaries are where framing bugs hide: feed the request one byte
/// at a time and stop decoding at the first request or error.
#[allow(dead_code)]
fn decode_byte_at_a_time(request: &[u8]) -> ProductionOutcome {
    let mut codec = Http1Codec::new();
    let mut src = BytesMut::new();
    for (index, byte) in request.iter().enumerate() {
        src.extend_from_slice(std::slice::from_ref(byte));
        match codec.decode(&mut src) {
            Ok(Some(decoded)) => {
                src.extend_from_slice(&request[index + 1..]);
                let remainder: &[u8] = src.as_ref();
                return ProductionOutcome::Decoded {
                    body: decoded.body,
                    trailers: decoded.trailers,
                    remainder: remainder.to_vec(),
                };
            }
            Ok(None) => {}
            Err(error) => return ProductionOutcome::Rejected(error),
        }
    }
    finish_at_eof(&mut codec, &mut src)
}

/// Run every production check for one case on a helper thread, bounded by
/// `PRODUCTION_DECODE_DEADLINE`.
#[allow(dead_code)]
fn probe_production(case: &ChunkedConformanceCase) -> Result<ProductionProbe, String> {
    let request = request_bytes(case);
    let size_line = case.size_line.map(|(line, _)| line);
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name(format!("rfc9112-chunked-{}", case.id))
        .spawn(move || {
            let probe = ProductionProbe {
                whole: decode_whole(&request),
                byte_at_a_time: decode_byte_at_a_time(&request),
                size_line: size_line.map(fuzz_parse_chunk_size_line),
            };
            let _ = sender.send(probe);
        })
        .map_err(|error| format!("could not spawn the decode thread: {error}"))?;
    match receiver.recv_timeout(PRODUCTION_DECODE_DEADLINE) {
        Ok(probe) => Ok(probe),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "production decode did not return within {PRODUCTION_DECODE_DEADLINE:?}"
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("production decode panicked: the decode thread ended without a result".to_string())
        }
    }
}

#[allow(dead_code)]
fn render_bytes(bytes: &[u8]) -> String {
    format!("\"{}\"", bytes.escape_ascii())
}

#[allow(dead_code)]
fn render_outcome(outcome: &ProductionOutcome) -> String {
    match outcome {
        ProductionOutcome::Decoded {
            body,
            trailers,
            remainder,
        } => format!(
            "Ok(Some(request)) body={} trailers={trailers:?} unconsumed={}",
            render_bytes(body),
            render_bytes(remainder)
        ),
        ProductionOutcome::NeedsMoreData { buffered, at_eof } => {
            let eof = match at_eof {
                EofOutcome::CleanEof => "Ok(None)".to_string(),
                EofOutcome::Delivered { body } => {
                    format!("Ok(Some(request)) body={}", render_bytes(body))
                }
                EofOutcome::Rejected(error) => format!("Err({error:?})"),
            };
            format!("Ok(None) with {buffered} bytes buffered; decode_eof -> {eof}")
        }
        ProductionOutcome::Rejected(error) => format!("Err({error:?})"),
    }
}

/// The framing errors that count as a refusal for `RejectOrDecodeAs`. Any
/// other error (a bad request line, a bad header) means the harness built a
/// bad request, so it does not count.
#[allow(dead_code)]
fn is_framing_rejection(error: &HttpError) -> bool {
    matches!(
        error,
        HttpError::BadChunkedEncoding
            | HttpError::BadTransferEncoding
            | HttpError::AmbiguousBodyLength
    )
}

#[allow(dead_code)]
fn check_decoded(
    case: &ChunkedConformanceCase,
    expected_body: &[u8],
    body: &[u8],
    trailers: &[(String, String)],
    remainder: &[u8],
) -> Result<(), String> {
    if body != expected_body {
        return Err(format!(
            "body {} differs from the expected {}",
            render_bytes(body),
            render_bytes(expected_body)
        ));
    }
    let trailers_match = trailers.len() == case.expected_trailers.len()
        && trailers.iter().zip(&case.expected_trailers).all(
            |((name, value), (expected_name, expected_value))| {
                name.eq_ignore_ascii_case(expected_name) && value.as_str() == *expected_value
            },
        );
    if !trailers_match {
        return Err(format!(
            "trailers {trailers:?} differ from the expected {:?}",
            case.expected_trailers
        ));
    }
    if remainder != case.expected_remainder {
        return Err(format!(
            "production left {} unconsumed, expected {}",
            render_bytes(remainder),
            render_bytes(case.expected_remainder)
        ));
    }
    Ok(())
}

/// Hold one production outcome against the RFC expectation the case encodes.
#[allow(dead_code)]
fn check_outcome(case: &ChunkedConformanceCase, outcome: &ProductionOutcome) -> Result<(), String> {
    match (&case.expected, outcome) {
        (
            ChunkedParseResult::Success(expected_body),
            ProductionOutcome::Decoded {
                body,
                trailers,
                remainder,
            },
        ) => check_decoded(case, expected_body, body, trailers, remainder),
        (
            ChunkedParseResult::MalformedChunk | ChunkedParseResult::InvalidChunkSize,
            ProductionOutcome::Rejected(HttpError::BadChunkedEncoding),
        ) => Ok(()),
        (
            ChunkedParseResult::MissingFinalChunk | ChunkedParseResult::Incomplete,
            ProductionOutcome::NeedsMoreData { buffered, at_eof },
        ) => {
            // Fail closed: an Ok(None) that never got past the request head
            // says nothing about the chunked body.
            if *buffered > case.input.len() {
                return Err(format!(
                    "production never consumed the request head: {buffered} bytes buffered for a {}-byte body",
                    case.input.len()
                ));
            }
            match at_eof {
                EofOutcome::Delivered { body } => Err(format!(
                    "decode_eof delivered an incomplete request with body {}",
                    render_bytes(body)
                )),
                EofOutcome::CleanEof | EofOutcome::Rejected(_) => Ok(()),
            }
        }
        (
            ChunkedParseResult::ChunkTooLarge,
            ProductionOutcome::Rejected(
                HttpError::BodyTooLarge
                | HttpError::BodyTooLargeDetailed { .. }
                | HttpError::BadChunkedEncoding,
            ),
        ) => Ok(()),
        (
            ChunkedParseResult::FramingRejected,
            ProductionOutcome::Rejected(HttpError::BadTransferEncoding),
        ) => Ok(()),
        (ChunkedParseResult::RejectOrDecodeAs(_), ProductionOutcome::Rejected(error))
            if is_framing_rejection(error) =>
        {
            Ok(())
        }
        (
            ChunkedParseResult::RejectOrDecodeAs(expected_body),
            ProductionOutcome::Decoded {
                body,
                trailers,
                remainder,
            },
        ) => check_decoded(case, expected_body, body, trailers, remainder),
        (ChunkedParseResult::NotObservable(reason), _) => {
            Err(format!("not observable through Http1Codec: {reason}"))
        }
        (expected, outcome) => Err(format!(
            "expected {expected:?}, production returned {}",
            render_outcome(outcome)
        )),
    }
}

/// Hold `fuzz_parse_chunk_size_line` against the case's size-line expectation.
#[allow(dead_code)]
fn check_size_line(
    case: &ChunkedConformanceCase,
    result: Option<&Result<usize, HttpError>>,
) -> Result<(), String> {
    match (case.size_line, result) {
        (None, _) => Ok(()),
        (Some((_, Some(expected))), Some(Ok(size))) if *size == expected => Ok(()),
        (Some((_, None)), Some(Err(HttpError::BadChunkedEncoding))) => Ok(()),
        (Some((line, expected)), result) => Err(format!(
            "fuzz_parse_chunk_size_line({}) returned {result:?}, expected {}",
            render_bytes(line),
            match expected {
                Some(size) => format!("Ok({size})"),
                None => "Err(BadChunkedEncoding)".to_string(),
            }
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every case id, in table order. Adding, removing or reordering a vector
    /// is a deliberate edit here.
    const EXPECTED_CASE_IDS: &[&str] = &[
        "RFC9112-7.1.1-simple-chunk",
        "RFC9112-7.1.1-multiple-chunks",
        "RFC9112-7.1.1-zero-final-chunk",
        "RFC9112-7.1.1-uppercase-hex",
        "RFC9112-7.1.1-lowercase-hex",
        "RFC9112-7.1.1-chunk-extensions",
        "RFC9112-7.1.1-trailers",
        "RFC9112-7.1.1-empty-chunk",
        "RFC9112-7.1.1-missing-crlf-after-size",
        "RFC9112-7.1.1-missing-crlf-after-data",
        "RFC9112-7.1.1-invalid-hex-chars",
        "RFC9112-7.1.1-size-too-large",
        "RFC9112-7.1.1-missing-final-chunk",
        "RFC9112-7.1-chunk-size-frames-embedded-terminator",
        "RFC9112-7.1-leading-zero-chunk-size",
        "RFC9112-7.1-invalid-hex-0x-prefix",
        "RFC9112-7.1-invalid-leading-whitespace-size",
        "RFC9112-7.1-chunk-size-overflow-wraps",
        "RFC9112-7.1-absurd-chunk-size",
        "RFC9112-7.1-truncated-chunk-data",
        "RFC9112-7.1-missing-final-crlf",
        "RFC9112-2.2-bare-lf-after-size",
        "RFC9112-2.2-bare-lf-after-data",
        "RFC9112-2.2-bare-lf-last-chunk",
        "RFC9112-2.2-bare-lf-in-chunk-ext",
        "RFC9112-6.1-te-and-cl",
        "RFC9112-6.1-cl-and-te",
        "RFC9112-6.3-chunked-not-final",
        "RFC9112-6.3-chunked-not-final-400-close",
        "RFC9112-6.1-te-and-cl-close",
    ];

    /// Main conformance test runner for RFC 9112 §7
    #[test]
    #[allow(dead_code)]
    fn rfc9112_section7_full_conformance() {
        let mut results = ConformanceResults::new();
        let cases = rfc9112_chunked_cases();

        for case in &cases {
            let verdict = run_conformance_case(case);
            results.record(case, verdict);
        }

        results.print_summary();
        results.assert_compliance();
    }

    #[allow(dead_code)]
    fn case_by_id(id: &str) -> ChunkedConformanceCase {
        match rfc9112_chunked_cases()
            .into_iter()
            .find(|case| case.id == id)
        {
            Some(case) => case,
            None => panic!("RFC 9112 chunked case {id} is missing from the vector table"),
        }
    }

    /// Decide one case from production: `Http1Codec` (whole buffer and one
    /// byte at a time) and, for size-line vectors, `fuzz_parse_chunk_size_line`.
    #[allow(dead_code)]
    fn run_conformance_case(case: &ChunkedConformanceCase) -> TestVerdict {
        if let ChunkedParseResult::NotObservable(reason) = &case.expected {
            eprintln!(
                "[rfc9112-chunked] case={} level={:?} verdict=skip reason={reason}",
                case.id, case.level
            );
            return TestVerdict::Skip {
                reason: (*reason).to_string(),
            };
        }

        let probe = match probe_production(case) {
            Ok(probe) => probe,
            Err(reason) => {
                eprintln!(
                    "[rfc9112-chunked] case={} level={:?} verdict=fail reason={reason}",
                    case.id, case.level
                );
                return TestVerdict::Fail { reason };
            }
        };

        let mut problems = Vec::new();
        if let Err(problem) = check_outcome(case, &probe.whole) {
            problems.push(format!("whole buffer: {problem}"));
        }
        if let Err(problem) = check_outcome(case, &probe.byte_at_a_time) {
            problems.push(format!("byte at a time: {problem}"));
        }
        if let Err(problem) = check_size_line(case, probe.size_line.as_ref()) {
            problems.push(problem);
        }

        eprintln!(
            "[rfc9112-chunked] case={} level={:?} verdict={} whole=[{}] byte_at_a_time=[{}] size_line={:?}",
            case.id,
            case.level,
            if problems.is_empty() { "pass" } else { "fail" },
            render_outcome(&probe.whole),
            render_outcome(&probe.byte_at_a_time),
            probe.size_line
        );

        if problems.is_empty() {
            TestVerdict::Pass
        } else {
            TestVerdict::Fail {
                reason: problems.join("; "),
            }
        }
    }

    #[derive(Debug)]
    #[allow(dead_code)]
    enum TestVerdict {
        Pass,
        Fail { reason: String },
        Skip { reason: String },
        ExpectedFail { reason: String },
    }

    #[allow(dead_code)]
    struct ConformanceResults {
        cases: Vec<CaseResult>,
    }

    #[allow(dead_code)]
    struct CaseResult {
        id: &'static str,
        level: RequirementLevel,
        verdict: TestVerdict,
    }

    #[allow(dead_code)]
    impl ConformanceResults {
        #[allow(dead_code)]
        fn new() -> Self {
            Self { cases: Vec::new() }
        }

        #[allow(dead_code)]
        fn record(&mut self, case: &ChunkedConformanceCase, verdict: TestVerdict) {
            self.cases.push(CaseResult {
                id: case.id,
                level: case.level,
                verdict,
            });
        }

        /// (passed, skipped, total) for one requirement level. A skipped case
        /// is not a pass.
        #[allow(dead_code)]
        fn tally(&self, level: RequirementLevel) -> (usize, usize, usize) {
            let mut passed = 0;
            let mut skipped = 0;
            let mut total = 0;
            for result in self.cases.iter().filter(|r| r.level == level) {
                total += 1;
                match result.verdict {
                    TestVerdict::Pass => passed += 1,
                    TestVerdict::Skip { .. } => skipped += 1,
                    TestVerdict::Fail { .. } | TestVerdict::ExpectedFail { .. } => {}
                }
            }
            (passed, skipped, total)
        }

        #[allow(dead_code)]
        fn print_summary(&self) {
            let mut failures = Vec::new();
            let mut skips = Vec::new();
            for result in &self.cases {
                match &result.verdict {
                    TestVerdict::Fail { reason } | TestVerdict::ExpectedFail { reason } => {
                        failures.push((result.id, result.level, reason));
                    }
                    TestVerdict::Skip { reason } => skips.push((result.id, result.level, reason)),
                    TestVerdict::Pass => {}
                }
            }

            eprintln!("\n=== RFC 9112 §7 Chunked Transfer Encoding Conformance (Http1Codec) ===");
            for (label, level) in [
                ("MUST requirements:  ", RequirementLevel::Must),
                ("SHOULD requirements:", RequirementLevel::Should),
                ("MAY requirements:   ", RequirementLevel::May),
            ] {
                let (passed, skipped, total) = self.tally(level);
                eprintln!(
                    "{label} {passed}/{total} pass ({:.1}%), {skipped} not observable (skipped)",
                    (passed as f64 / total as f64) * 100.0
                );
            }

            if !failures.is_empty() {
                eprintln!("\nFailures:");
                for (id, level, reason) in failures {
                    eprintln!("  {id} [{level:?}]: {reason}");
                }
            }
            if !skips.is_empty() {
                eprintln!("\nNot observable through Http1Codec (skipped, not counted as pass):");
                for (id, level, reason) in skips {
                    eprintln!("  {id} [{level:?}]: {reason}");
                }
            }
        }

        #[allow(dead_code)]
        fn assert_compliance(&self) {
            let must_failures: Vec<_> = self
                .cases
                .iter()
                .filter(|r| r.level == RequirementLevel::Must)
                .filter(|r| {
                    matches!(
                        r.verdict,
                        TestVerdict::Fail { .. } | TestVerdict::ExpectedFail { .. }
                    )
                })
                .map(|r| r.id)
                .collect();

            if !must_failures.is_empty() {
                panic!("RFC 9112 §7 MUST requirement failures: {:?}", must_failures);
            }

            // A skip is never a pass, and only the declared not-observable
            // requirements may skip, so no case can leave production checking
            // unnoticed.
            let skipped: Vec<&str> = self
                .cases
                .iter()
                .filter(|r| matches!(r.verdict, TestVerdict::Skip { .. }))
                .map(|r| r.id)
                .collect();
            assert_eq!(
                skipped, NOT_OBSERVABLE_CASE_IDS,
                "only the declared not-observable RFC 9112 requirements may be skipped"
            );

            let passed = self
                .cases
                .iter()
                .filter(|r| matches!(r.verdict, TestVerdict::Pass))
                .count();
            assert!(
                passed > 0,
                "no RFC 9112 §7 case passed against Http1Codec; the run decided nothing"
            );
        }
    }

    /// Individual test cases for easier debugging

    #[test]
    #[allow(dead_code)]
    fn rfc9112_simple_chunked_body() {
        let case = case_by_id("RFC9112-7.1.1-simple-chunk");
        let verdict = run_conformance_case(&case);
        assert!(
            matches!(verdict, TestVerdict::Pass),
            "Simple chunk test failed: {:?}",
            verdict
        );
    }

    #[test]
    #[allow(dead_code)]
    fn rfc9112_multiple_chunks() {
        let case = case_by_id("RFC9112-7.1.1-multiple-chunks");
        let verdict = run_conformance_case(&case);
        assert!(
            matches!(verdict, TestVerdict::Pass),
            "Multiple chunks test failed: {:?}",
            verdict
        );
    }

    #[test]
    #[allow(dead_code)]
    fn rfc9112_case_insensitive_hex() {
        // Test both uppercase and lowercase hex
        for id in ["RFC9112-7.1.1-uppercase-hex", "RFC9112-7.1.1-lowercase-hex"] {
            let case = case_by_id(id);
            let verdict = run_conformance_case(&case);
            assert!(
                matches!(verdict, TestVerdict::Pass),
                "Case insensitive hex test {} failed: {:?}",
                case.id,
                verdict
            );
        }
    }

    #[test]
    #[allow(dead_code)]
    fn rfc9112_chunk_extensions() {
        let case = case_by_id("RFC9112-7.1.1-chunk-extensions");
        let verdict = run_conformance_case(&case);
        assert!(
            matches!(verdict, TestVerdict::Pass),
            "Chunk extensions test failed: {:?}",
            verdict
        );
    }

    #[test]
    #[allow(dead_code)]
    fn rfc9112_trailer_headers() {
        let case = case_by_id("RFC9112-7.1.1-trailers");
        let verdict = run_conformance_case(&case);
        assert!(
            matches!(verdict, TestVerdict::Pass),
            "Trailers test failed: {:?}",
            verdict
        );
    }

    #[test]
    #[allow(dead_code)]
    fn rfc9112_error_cases() {
        // Every MUST-level vector that production has to refuse, or hold as
        // incomplete, selected by its expectation rather than by its id.
        let cases = rfc9112_chunked_cases();
        let mut checked = 0;
        for case in &cases {
            let must_refuse = case.level == RequirementLevel::Must
                && !matches!(
                    case.expected,
                    ChunkedParseResult::Success(_) | ChunkedParseResult::NotObservable(_)
                );
            if must_refuse {
                checked += 1;
                let verdict = run_conformance_case(case);
                assert!(
                    matches!(verdict, TestVerdict::Pass),
                    "Error case {} must be refused or held incomplete: {:?}",
                    case.id,
                    verdict
                );
            }
        }
        assert!(
            checked > 0,
            "no MUST-level error vector was selected; the test checked nothing"
        );
    }

    /// Inventory guard for local RFC 9112 chunked vectors.
    #[test]
    #[allow(dead_code)]
    fn rfc9112_local_vector_inventory_is_explicit() {
        let cases = rfc9112_chunked_cases();
        let ids: Vec<&str> = cases.iter().map(|case| case.id).collect();
        assert_eq!(
            ids, EXPECTED_CASE_IDS,
            "the RFC 9112 chunked vector inventory changed; update EXPECTED_CASE_IDS on purpose"
        );

        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ids.len(), "duplicate case ids: {ids:?}");

        let not_observable: Vec<&str> = cases
            .iter()
            .filter(|case| matches!(case.expected, ChunkedParseResult::NotObservable(_)))
            .map(|case| case.id)
            .collect();
        assert_eq!(
            not_observable, NOT_OBSERVABLE_CASE_IDS,
            "the set of requirements marked not observable changed"
        );

        // Every other case is a complete request that production decodes.
        for case in &cases {
            if matches!(case.expected, ChunkedParseResult::NotObservable(_)) {
                continue;
            }
            assert!(
                case.head.starts_with(b"POST /p HTTP/1.1\r\n") && case.head.ends_with(b"\r\n\r\n"),
                "case {} does not carry a complete request head",
                case.id
            );
            assert!(!case.input.is_empty(), "case {} has no body bytes", case.id);
        }
    }
}
