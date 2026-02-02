#![allow(clippy::similar_names)]
//! HTTP/2 Security Hardening Integration Tests (bd-1z7e).
//!
//! Verifies that all security fixes from the HTTP/2 Security Hardening epic
//! (bd-1bic) are correct, tested against malicious inputs, and compliant
//! with RFC 7540/7541.

#![allow(clippy::items_after_statements)]

mod common;
use common::*;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::error::{ErrorCode, H2Error};
use asupersync::http::h2::frame::{
    FrameHeader, FRAME_HEADER_SIZE, MAX_FRAME_SIZE, MIN_MAX_FRAME_SIZE,
};
use asupersync::http::h2::hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder, Header};
use asupersync::http::h2::settings::SettingsBuilder;
use asupersync::http::h2::stream::StreamStore;

// ===========================================================================
// Section 1: HPACK Integer Overflow Protection
// ===========================================================================

#[test]
fn hpack_integer_overflow_rejected() {
    init_test_logging();
    test_phase!("hpack_integer_overflow");

    let mut decoder = HpackDecoder::new();

    // Craft a header block with an integer that overflows usize.
    // 0x00 = literal header without indexing, new name
    // Then a string length encoded as a huge integer
    let malicious: &[u8] = &[
        0x00, // Literal header, not indexed, new name
        0x7f, // String length prefix = 127 (needs continuation)
        0xff, 0xff, 0xff, 0xff, 0x0f, // Continuation: would overflow
    ];
    let mut src = Bytes::from_static(malicious);
    let result = decoder.decode(&mut src);
    assert!(result.is_err(), "integer overflow should be rejected");

    test_complete!("hpack_integer_overflow");
}

#[test]
fn hpack_integer_shift_overflow_rejected() {
    init_test_logging();
    test_phase!("hpack_integer_shift_overflow");

    let mut decoder = HpackDecoder::new();

    // Construct bytes that force shift > 28 bits
    // 0x00 = literal header without indexing, new name
    // 0x7f = prefix filled (127)
    // Then many continuation bytes to push shift past 28
    let mut malicious = vec![0x00u8, 0x7f];
    malicious.extend(std::iter::repeat_n(0x80, 6)); // Continuation bytes with value 0
    malicious.push(0x01); // Final byte

    let mut src = Bytes::from(malicious);
    let result = decoder.decode(&mut src);
    assert!(result.is_err(), "shift overflow should be rejected");

    test_complete!("hpack_integer_shift_overflow");
}

// ===========================================================================
// Section 2: HPACK Dynamic Table Size Cap
// ===========================================================================

#[test]
fn hpack_table_size_capped_at_1mb() {
    init_test_logging();
    test_phase!("hpack_table_size_cap");

    let mut decoder = HpackDecoder::new();

    // Try to set table size to 2MB via a size update instruction
    // 0x20 = dynamic table size update prefix
    // Encode 2_097_152 (2MB) as HPACK integer with 5-bit prefix
    let mut malicious = BytesMut::new();
    malicious.extend_from_slice(&[
        0x3f, // Size update prefix (0x20 | 0x1f = 63)
        0xe1, 0xff, 0x7f, // Encode 2MB - 31 = 2097121 in continuation
    ]);
    let mut src = malicious.freeze();
    let result = decoder.decode(&mut src);
    assert!(result.is_err(), "table size > 1MB should be rejected");

    test_complete!("hpack_table_size_cap");
}

#[test]
fn hpack_consecutive_size_updates_limited() {
    init_test_logging();
    test_phase!("hpack_consecutive_size_updates");

    let mut decoder = HpackDecoder::new();

    // Send 17 consecutive size update instructions (limit is 16)
    let mut malicious = vec![0x20; 17]; // 17 consecutive size update instructions (limit is 16)
                                        // Follow with a valid indexed header to trigger decoding
    malicious.push(0x82); // :method GET (static index 2)

    let mut src = Bytes::from(malicious);
    let result = decoder.decode(&mut src);
    assert!(
        result.is_err(),
        "more than 16 consecutive size updates should be rejected"
    );

    test_complete!("hpack_consecutive_size_updates");
}

// ===========================================================================
// Section 3: Huffman Decoding Security
// ===========================================================================

#[test]
fn huffman_invalid_padding_no_panic() {
    init_test_logging();
    test_phase!("huffman_invalid_padding");

    let mut decoder = HpackDecoder::new();

    // Literal header with Huffman-encoded value that has invalid padding
    let malicious: &[u8] = &[
        0x00, // Literal header, not indexed, new name
        0x01, 0x78, // Name: literal "x" (length 1)
        0x81, // Value: Huffman flag set, length 1
        0x00, // Invalid huffman byte (padding not all 1s)
    ];
    let mut src = Bytes::from_static(malicious);
    // Must not panic - error or ok both acceptable
    let _ = decoder.decode(&mut src);

    test_complete!("huffman_invalid_padding");
}

#[test]
fn huffman_truncated_symbol_no_panic() {
    init_test_logging();
    test_phase!("huffman_truncated_symbol");

    let mut decoder = HpackDecoder::new();

    // Literal header with a truncated Huffman value
    let malicious: &[u8] = &[
        0x00, // Literal header, not indexed, new name
        0x01, 0x78, // Name: "x"
        0x82, // Value: Huffman flag, length 2
        0xff, // Only 1 byte when 2 expected
    ];
    let mut src = Bytes::from_static(malicious);
    // Must not panic
    let _ = decoder.decode(&mut src);

    test_complete!("huffman_truncated_symbol");
}

// ===========================================================================
// Section 4: Frame Header Parsing Security
// ===========================================================================

#[test]
fn frame_header_parse_basic() {
    init_test_logging();
    test_phase!("frame_header_parse_basic");

    // Construct a valid 9-byte frame header for a DATA frame
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE);
    // Length: 100 (3 bytes big-endian)
    buf.extend_from_slice(&[0x00, 0x00, 0x64]);
    // Type: DATA (0x0)
    buf.extend_from_slice(&[0x00]);
    // Flags: END_STREAM (0x1)
    buf.extend_from_slice(&[0x01]);
    // Stream ID: 1 (4 bytes big-endian, high bit reserved)
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    let header = FrameHeader::parse(&mut buf).expect("valid frame header");
    assert_eq!(header.length, 100);
    assert_eq!(header.frame_type, 0x00);
    assert_eq!(header.flags, 0x01);
    assert_eq!(header.stream_id, 1);

    test_complete!("frame_header_parse_basic");
}

#[test]
fn frame_header_reserved_bit_masked() {
    init_test_logging();
    test_phase!("frame_header_reserved_bit");

    // Stream ID with reserved high bit set (should be masked off)
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE);
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // Length 0
    buf.extend_from_slice(&[0x00]); // Type DATA
    buf.extend_from_slice(&[0x00]); // Flags
    buf.extend_from_slice(&[0x80, 0x00, 0x00, 0x01]); // Stream ID 1 with reserved bit set

    let header = FrameHeader::parse(&mut buf).expect("valid frame header");
    assert_eq!(header.stream_id, 1, "reserved bit must be masked");

    test_complete!("frame_header_reserved_bit");
}

#[test]
fn frame_header_insufficient_bytes() {
    init_test_logging();
    test_phase!("frame_header_insufficient");

    let mut buf = BytesMut::from(&[0x00, 0x00][..]);
    let result = FrameHeader::parse(&mut buf);
    assert!(result.is_err(), "insufficient bytes should error");

    test_complete!("frame_header_insufficient");
}

// ===========================================================================
// Section 5: Settings Validation
// ===========================================================================

#[test]
fn settings_max_frame_size_bounds() {
    init_test_logging();
    test_phase!("settings_max_frame_size_bounds");

    // Valid range: 16384 to 16777215
    let settings = SettingsBuilder::new()
        .max_frame_size(MIN_MAX_FRAME_SIZE)
        .build();
    assert_eq!(settings.max_frame_size, MIN_MAX_FRAME_SIZE);

    let settings = SettingsBuilder::new()
        .max_frame_size(MAX_FRAME_SIZE)
        .build();
    assert_eq!(settings.max_frame_size, MAX_FRAME_SIZE);

    // Below minimum should clamp
    let settings = SettingsBuilder::new().max_frame_size(100).build();
    assert_eq!(settings.max_frame_size, MIN_MAX_FRAME_SIZE);

    test_complete!("settings_max_frame_size_bounds");
}

#[test]
fn settings_header_table_size() {
    init_test_logging();
    test_phase!("settings_header_table_size");

    let settings = SettingsBuilder::new().header_table_size(0).build();
    assert_eq!(settings.header_table_size, 0);

    let settings = SettingsBuilder::new().header_table_size(65536).build();
    assert_eq!(settings.header_table_size, 65536);

    test_complete!("settings_header_table_size");
}

// ===========================================================================
// Section 6: Stream State Machine
// ===========================================================================

#[test]
fn stream_store_basic_operations() {
    init_test_logging();
    test_phase!("stream_store_basic");

    let mut store = StreamStore::new(true, 65535, 16384);
    // get_or_create should create streams on demand
    let result = store.get_or_create(1);
    assert!(result.is_ok(), "creating stream 1 should succeed");

    let stream = store.get(1);
    assert!(stream.is_some(), "stream 1 should exist after creation");

    test_complete!("stream_store_basic");
}

#[test]
fn stream_store_multiple_streams() {
    init_test_logging();
    test_phase!("stream_store_multiple");

    let mut store = StreamStore::new(true, 65535, 16384);
    store.get_or_create(1).expect("create stream 1");
    store.get_or_create(3).expect("create stream 3");
    store.get_or_create(5).expect("create stream 5");

    assert!(store.get(1).is_some());
    assert!(store.get(3).is_some());
    assert!(store.get(5).is_some());
    assert!(store.get(7).is_none());

    test_complete!("stream_store_multiple");
}

// ===========================================================================
// Section 7: Encoder/Decoder Roundtrip
// ===========================================================================

#[test]
fn hpack_roundtrip_standard_headers() {
    init_test_logging();
    test_phase!("hpack_roundtrip_standard");

    let headers = vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
        Header::new("accept", "text/html"),
    ];

    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    let mut buf = BytesMut::new();
    encoder.encode(&headers, &mut buf);

    let mut src = buf.freeze();
    let decoded = decoder.decode(&mut src).expect("decode should succeed");

    assert_eq!(decoded.len(), headers.len());
    for (orig, dec) in headers.iter().zip(decoded.iter()) {
        assert_eq!(orig.name, dec.name);
        assert_eq!(orig.value, dec.value);
    }

    test_complete!("hpack_roundtrip_standard");
}

#[test]
fn hpack_roundtrip_with_huffman() {
    init_test_logging();
    test_phase!("hpack_roundtrip_huffman");

    let headers = vec![
        Header::new(":method", "POST"),
        Header::new(":path", "/api/v1/users"),
        Header::new("content-type", "application/json"),
        Header::new("authorization", "Bearer abc123xyz"),
    ];

    let mut encoder = HpackEncoder::new();
    encoder.set_use_huffman(true);
    let mut decoder = HpackDecoder::new();

    let mut buf = BytesMut::new();
    encoder.encode(&headers, &mut buf);

    let mut src = buf.freeze();
    let decoded = decoder.decode(&mut src).expect("decode should succeed");

    assert_eq!(decoded.len(), headers.len());
    for (orig, dec) in headers.iter().zip(decoded.iter()) {
        assert_eq!(orig.name, dec.name);
        assert_eq!(orig.value, dec.value);
    }

    test_complete!("hpack_roundtrip_huffman");
}

#[test]
fn hpack_sensitive_headers_not_indexed() {
    init_test_logging();
    test_phase!("hpack_sensitive_headers");

    let sensitive = vec![
        Header::new("authorization", "Bearer secret-token"),
        Header::new("cookie", "session=abc123"),
    ];

    let mut encoder = HpackEncoder::new();
    let mut buf = BytesMut::new();
    encoder.encode_sensitive(&sensitive, &mut buf);

    // Verify the encoded bytes use "never indexed" representation (0x10 prefix)
    let first_byte = buf[0];
    assert_eq!(
        first_byte & 0xf0,
        0x10,
        "sensitive headers should use never-indexed representation"
    );

    // Roundtrip should still work
    let mut decoder = HpackDecoder::new();
    let mut src = buf.freeze();
    let decoded = decoder.decode(&mut src).expect("decode should succeed");
    assert_eq!(decoded.len(), sensitive.len());

    test_complete!("hpack_sensitive_headers");
}

// ===========================================================================
// Section 8: Dynamic Table Eviction Under Pressure
// ===========================================================================

#[test]
fn hpack_dynamic_table_eviction_under_rapid_inserts() {
    init_test_logging();
    test_phase!("hpack_dynamic_table_eviction");

    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // Send many unique headers to force table eviction
    for i in 0..200 {
        let headers = vec![Header::new(
            format!("x-custom-{i}"),
            format!("value-{i}-padding-to-fill-table"),
        )];

        let mut buf = BytesMut::new();
        encoder.encode(&headers, &mut buf);

        let mut src = buf.freeze();
        let decoded = decoder.decode(&mut src).expect("decode should succeed");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, format!("x-custom-{i}"));
    }

    test_complete!("hpack_dynamic_table_eviction");
}

// ===========================================================================
// Section 9: Malformed Input Resilience
// ===========================================================================

#[test]
fn hpack_decoder_handles_empty_input() {
    init_test_logging();
    test_phase!("hpack_empty_input");

    let mut decoder = HpackDecoder::new();
    let mut src = Bytes::new();
    let result = decoder
        .decode(&mut src)
        .expect("empty input should succeed");
    assert!(result.is_empty());

    test_complete!("hpack_empty_input");
}

#[test]
fn hpack_decoder_handles_random_bytes() {
    init_test_logging();
    test_phase!("hpack_random_bytes");

    let mut decoder = HpackDecoder::new();

    // Test 100 random-ish byte sequences - must not panic
    for seed in 0u8..100 {
        let data: Vec<u8> = (0..32)
            .map(|i| seed.wrapping_mul(i).wrapping_add(i))
            .collect();
        let mut src = Bytes::from(data);
        let _ = decoder.decode(&mut src);
    }

    test_complete!("hpack_random_bytes");
}

#[test]
fn hpack_indexed_zero_rejected() {
    init_test_logging();
    test_phase!("hpack_indexed_zero");

    let mut decoder = HpackDecoder::new();
    // 0x80 = indexed header, index 0 (invalid per RFC 7541)
    let mut src = Bytes::from_static(&[0x80]);
    let result = decoder.decode(&mut src);
    assert!(result.is_err(), "index 0 should be rejected");

    test_complete!("hpack_indexed_zero");
}

#[test]
fn hpack_header_list_size_exceeded() {
    init_test_logging();
    test_phase!("hpack_header_list_size");

    let mut decoder = HpackDecoder::new();
    decoder.set_max_header_list_size(100);

    // Encode headers that exceed 100 bytes total
    let mut encoder = HpackEncoder::new();
    let headers = vec![Header::new("x-big-header", "a".repeat(100))];
    let mut buf = BytesMut::new();
    encoder.encode(&headers, &mut buf);

    let mut src = buf.freeze();
    let result = decoder.decode(&mut src);
    assert!(
        result.is_err(),
        "header list exceeding max size should be rejected"
    );

    test_complete!("hpack_header_list_size");
}

#[test]
fn hpack_out_of_range_static_index() {
    init_test_logging();
    test_phase!("hpack_out_of_range_index");

    let mut decoder = HpackDecoder::new();
    // Index 62+ with empty dynamic table should fail
    // 0xbe = indexed header, index 62 (static table only has 61 entries)
    let mut src = Bytes::from_static(&[0xbe]);
    let result = decoder.decode(&mut src);
    assert!(result.is_err(), "out-of-range index should be rejected");

    test_complete!("hpack_out_of_range_index");
}

// ===========================================================================
// Section 10: Error Code Coverage
// ===========================================================================

#[test]
fn error_code_roundtrip() {
    init_test_logging();
    test_phase!("error_code_roundtrip");

    let codes = [
        (0x0, ErrorCode::NoError),
        (0x1, ErrorCode::ProtocolError),
        (0x3, ErrorCode::FlowControlError),
        (0x6, ErrorCode::FrameSizeError),
        (0x9, ErrorCode::CompressionError),
        (0xb, ErrorCode::EnhanceYourCalm),
        (0xd, ErrorCode::Http11Required),
    ];

    for (val, expected) in &codes {
        let code = ErrorCode::from_u32(*val);
        assert_eq!(code, *expected);
        assert_eq!(u32::from(code), *val);
    }

    // Unknown codes map to InternalError
    assert_eq!(ErrorCode::from_u32(0xff), ErrorCode::InternalError);

    test_complete!("error_code_roundtrip");
}

#[test]
fn h2_error_display() {
    init_test_logging();
    test_phase!("h2_error_display");

    let conn_err = H2Error::connection(ErrorCode::ProtocolError, "test");
    assert!(conn_err.is_connection_error());
    let msg = format!("{conn_err}");
    assert!(msg.contains("PROTOCOL_ERROR"));

    let stream_err = H2Error::stream(1, ErrorCode::Cancel, "cancelled");
    assert!(!stream_err.is_connection_error());
    let msg = format!("{stream_err}");
    assert!(msg.contains("stream 1"));

    test_complete!("h2_error_display");
}

#[test]
fn h2_error_convenience_constructors() {
    init_test_logging();
    test_phase!("h2_error_constructors");

    let err = H2Error::protocol("test");
    assert_eq!(err.code, ErrorCode::ProtocolError);

    let err = H2Error::frame_size("too big");
    assert_eq!(err.code, ErrorCode::FrameSizeError);

    let err = H2Error::flow_control("exceeded");
    assert_eq!(err.code, ErrorCode::FlowControlError);

    let err = H2Error::compression("bad hpack");
    assert_eq!(err.code, ErrorCode::CompressionError);

    test_complete!("h2_error_constructors");
}

// ===========================================================================
// Section 11: RFC 7541 Static Table Compliance
// ===========================================================================

#[test]
fn static_table_pseudoheaders_indexed() {
    init_test_logging();
    test_phase!("static_table_pseudoheaders");

    let mut decoder = HpackDecoder::new();

    // Index 2 = :method GET
    let mut src = Bytes::from_static(&[0x82]);
    let headers = decoder.decode(&mut src).expect("decode indexed header");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":method");
    assert_eq!(headers[0].value, "GET");

    // Index 4 = :path /
    let mut src = Bytes::from_static(&[0x84]);
    let headers = decoder.decode(&mut src).expect("decode indexed header");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":path");
    assert_eq!(headers[0].value, "/");

    // Index 7 = :scheme https
    let mut src = Bytes::from_static(&[0x87]);
    let headers = decoder.decode(&mut src).expect("decode indexed header");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name, ":scheme");
    assert_eq!(headers[0].value, "https");

    test_complete!("static_table_pseudoheaders");
}

#[test]
fn static_table_status_codes_indexed() {
    init_test_logging();
    test_phase!("static_table_status_codes");

    let mut decoder = HpackDecoder::new();

    // Index 8 = :status 200
    let mut src = Bytes::from_static(&[0x88]);
    let headers = decoder.decode(&mut src).expect("decode indexed header");
    assert_eq!(headers[0].name, ":status");
    assert_eq!(headers[0].value, "200");

    // Index 13 = :status 404
    let mut src = Bytes::from_static(&[0x8d]);
    let headers = decoder.decode(&mut src).expect("decode indexed header");
    assert_eq!(headers[0].name, ":status");
    assert_eq!(headers[0].value, "404");

    test_complete!("static_table_status_codes");
}
