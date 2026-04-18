//! HPACK Continuation Frame Conformance Tests
//!
//! Tests compliance with RFC 7541 Section 4.3: Header Block Processing
//! and RFC 7540 Section 6.10: CONTINUATION frames.
//!
//! Key requirements:
//! 1. HEADERS+CONTINUATION frames decode as single logical header block
//! 2. Dynamic table updates work correctly across fragmented header blocks
//! 3. END_HEADERS flag semantics are enforced properly
//! 4. Header block fragmentation boundaries are arbitrary
//!
//! This module tests edge cases and conformance requirements that basic unit
//! tests don't cover, ensuring proper RFC compliance for header block fragmentation.

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    frame::{ContinuationFrame, FrameHeader},
    stream::Stream,
    hpack::{Decoder as HpackDecoder, Encoder as HpackEncoder, Header},
    settings::DEFAULT_MAX_HEADER_LIST_SIZE,
};

/// Test that HEADERS+CONTINUATION frames decode as a single logical header block
#[test]
fn headers_plus_continuation_single_block_decode() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // Create a large header set that will require fragmentation
    let headers = vec![
        Header::new(":method", "GET"),
        Header::new(":path", "/very/long/path/that/might/need/fragmentation"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "example.com"),
        Header::new("user-agent", "test-agent/1.0 with a very long user agent string"),
        Header::new("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        Header::new("accept-language", "en-US,en;q=0.5"),
        Header::new("accept-encoding", "gzip, deflate, br"),
        Header::new("custom-header", "custom-value-with-lots-of-data-to-force-fragmentation"),
    ];

    // Encode headers into a single block
    let mut encoded_block = BytesMut::new();
    encoder.encode(&headers, &mut encoded_block);

    // Fragment the encoded block at an arbitrary boundary (not header boundary)
    let fragment_point = encoded_block.len() / 3;
    let fragment1 = encoded_block.split_to(fragment_point).freeze();
    let fragment2 = encoded_block.freeze();

    // Simulate receiving HEADERS frame (without END_HEADERS) + CONTINUATION frame
    let mut stream = Stream::new(1, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

    // Receive headers without END_HEADERS
    stream.recv_headers(false, false).unwrap();
    stream.add_header_fragment(fragment1).unwrap();

    // Receive continuation with END_HEADERS
    stream.recv_continuation(fragment2, true).unwrap();

    // Reconstruct the complete header block
    let fragments = stream.take_header_fragments();
    let mut complete_block = BytesMut::new();
    for fragment in fragments {
        complete_block.extend_from_slice(&fragment);
    }

    // Decode the reconstructed block
    let mut header_bytes = complete_block.freeze();
    let decoded_headers = decoder.decode(&mut header_bytes).unwrap();

    // Verify all headers were decoded correctly
    assert_eq!(decoded_headers.len(), headers.len());
    for (expected, actual) in headers.iter().zip(decoded_headers.iter()) {
        assert_eq!(expected.name, actual.name);
        assert_eq!(expected.value, actual.value);
    }
}

/// Test dynamic table updates across header block fragments
#[test]
fn dynamic_table_updates_across_fragments() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // First, populate dynamic table with some entries
    let setup_headers = vec![
        Header::new("custom-header-1", "value1"),
        Header::new("custom-header-2", "value2"),
    ];

    let mut setup_block = BytesMut::new();
    encoder.encode(&setup_headers, &mut setup_block);
    let mut setup_bytes = setup_block.freeze();
    decoder.decode(&mut setup_bytes).unwrap();

    // Create a header block with dynamic table size update followed by headers
    let mut encoded_block = BytesMut::new();

    // Set dynamic table size update (RFC 7541 Section 4.2)
    encoder.set_max_table_size(2048);

    // Add headers that reference the dynamic table
    let test_headers = vec![
        Header::new("custom-header-1", "new-value1"), // Should reference index from dynamic table
        Header::new(":method", "POST"),
        Header::new("custom-header-3", "value3"),
    ];

    encoder.encode(&test_headers, &mut encoded_block);

    // Fragment the block to put table update in first fragment and some headers in second
    // This tests that table updates work correctly when fragmented
    let table_update_size = 2; // Approximate size of table size update
    let fragment_point = table_update_size + 10; // Split after table update but during headers

    let fragment1 = encoded_block.split_to(fragment_point).freeze();
    let fragment2 = encoded_block.freeze();

    // Process as fragmented header block
    let mut stream = Stream::new(2, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
    stream.recv_headers(false, false).unwrap();
    stream.add_header_fragment(fragment1).unwrap();
    stream.recv_continuation(fragment2, true).unwrap();

    // Reconstruct and decode
    let fragments = stream.take_header_fragments();
    let mut complete_block = BytesMut::new();
    for fragment in fragments {
        complete_block.extend_from_slice(&fragment);
    }

    let mut complete_bytes = complete_block.freeze();
    let decoded_headers = decoder.decode(&mut complete_bytes).unwrap();

    // Verify headers decoded correctly despite fragmentation across table update
    assert_eq!(decoded_headers.len(), test_headers.len());
    for (expected, actual) in test_headers.iter().zip(decoded_headers.iter()) {
        assert_eq!(expected.name, actual.name);
        assert_eq!(expected.value, actual.value);
    }
}

/// Test END_HEADERS flag semantics and enforcement
#[test]
fn end_headers_flag_semantics() {
    let mut stream = Stream::new(3, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

    // Start receiving headers without END_HEADERS
    stream.recv_headers(false, false).unwrap();
    assert!(stream.is_receiving_headers());

    // Add continuation without END_HEADERS
    stream.recv_continuation(Bytes::from_static(b"fragment1"), false).unwrap();
    assert!(stream.is_receiving_headers());

    // Add another continuation without END_HEADERS
    stream.recv_continuation(Bytes::from_static(b"fragment2"), false).unwrap();
    assert!(stream.is_receiving_headers());

    // Final continuation with END_HEADERS should complete the block
    stream.recv_continuation(Bytes::from_static(b"fragment3"), true).unwrap();
    assert!(!stream.is_receiving_headers());

    // Verify all fragments were collected
    let fragments = stream.take_header_fragments();
    assert_eq!(fragments.len(), 3);
    assert_eq!(&fragments[0][..], b"fragment1");
    assert_eq!(&fragments[1][..], b"fragment2");
    assert_eq!(&fragments[2][..], b"fragment3");
}

/// Test that CONTINUATION frames are rejected when no header block is in progress
#[test]
fn continuation_rejected_when_no_headers_in_progress() {
    let mut stream = Stream::new(4, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

    // Stream should initially have headers_complete = true
    assert!(!stream.is_receiving_headers());

    // CONTINUATION frame should be rejected
    let result = stream.recv_continuation(Bytes::from_static(b"test"), false);
    assert!(result.is_err());
    let error_msg = format!("{}", result.unwrap_err());
    assert!(error_msg.contains("protocol") || error_msg.contains("unexpected") || error_msg.contains("receiving"));
}

/// Test header block fragmentation at arbitrary byte boundaries
#[test]
fn fragmentation_at_arbitrary_boundaries() {
    let mut encoder = HpackEncoder::new();
    let _decoder = HpackDecoder::new();

    // Create headers with mixed encoding (indexed, literal, etc.)
    let headers = vec![
        Header::new(":method", "GET"),           // Should be indexed
        Header::new(":path", "/test"),           // Should be indexed
        Header::new("custom", "value"),          // Literal
        Header::new("x-test", "data"),          // Literal
    ];

    let mut encoded_block = BytesMut::new();
    encoder.encode(&headers, &mut encoded_block);

    let total_len = encoded_block.len();

    // Test fragmentation at every possible byte boundary
    for split_point in 1..total_len {
        let mut test_encoder = HpackEncoder::new();
        let mut test_decoder = HpackDecoder::new();

        // Re-encode for fresh state
        let mut fresh_block = BytesMut::new();
        test_encoder.encode(&headers, &mut fresh_block);

        // Fragment at this boundary
        let fragment1 = fresh_block.split_to(split_point).freeze();
        let fragment2 = fresh_block.freeze();

        // Process fragments
        let mut stream = Stream::new(5 + split_point as u32, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);
        stream.recv_headers(false, false).unwrap();
        stream.add_header_fragment(fragment1).unwrap();
        stream.recv_continuation(fragment2, true).unwrap();

        // Reconstruct and decode
        let fragments = stream.take_header_fragments();
        let mut complete_block = BytesMut::new();
        for fragment in fragments {
            complete_block.extend_from_slice(&fragment);
        }

        // Decode should succeed regardless of fragment boundary
        let mut header_block = complete_block.freeze();
        let decoded_headers = test_decoder.decode(&mut header_block).unwrap();
        assert_eq!(decoded_headers.len(), headers.len());

        // Verify content is correct
        for (expected, actual) in headers.iter().zip(decoded_headers.iter()) {
            assert_eq!(expected.name, actual.name);
            assert_eq!(expected.value, actual.value);
        }
    }
}

/// Test multiple CONTINUATION frames with proper sequencing
#[test]
fn multiple_continuation_frames() {
    let mut encoder = HpackEncoder::new();
    let mut decoder = HpackDecoder::new();

    // Create a large header block that will be split into multiple fragments
    let headers = vec![
        Header::new(":method", "POST"),
        Header::new(":path", "/api/v1/endpoint"),
        Header::new(":scheme", "https"),
        Header::new(":authority", "api.example.com"),
        Header::new("content-type", "application/json"),
        Header::new("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        Header::new("x-request-id", "550e8400-e29b-41d4-a716-446655440000"),
        Header::new("user-agent", "MyApp/1.0 (compatible; HTTPClient/1.0)"),
    ];

    let mut encoded_block = BytesMut::new();
    encoder.encode(&headers, &mut encoded_block);

    // Split into 4 fragments of roughly equal size
    let total_len = encoded_block.len();
    let fragment_size = total_len / 4;

    let fragment1 = encoded_block.split_to(fragment_size).freeze();
    let fragment2 = encoded_block.split_to(fragment_size).freeze();
    let fragment3 = encoded_block.split_to(fragment_size).freeze();
    let fragment4 = encoded_block.freeze(); // Remainder

    // Process as HEADERS + 3 CONTINUATION frames
    let mut stream = Stream::new(6, 65535, DEFAULT_MAX_HEADER_LIST_SIZE);

    // HEADERS frame without END_HEADERS
    stream.recv_headers(false, false).unwrap();
    stream.add_header_fragment(fragment1).unwrap();

    // First CONTINUATION without END_HEADERS
    stream.recv_continuation(fragment2, false).unwrap();

    // Second CONTINUATION without END_HEADERS
    stream.recv_continuation(fragment3, false).unwrap();

    // Final CONTINUATION with END_HEADERS
    stream.recv_continuation(fragment4, true).unwrap();

    // Verify header reception is complete
    assert!(!stream.is_receiving_headers());

    // Reconstruct and decode
    let fragments = stream.take_header_fragments();
    assert_eq!(fragments.len(), 4);

    let mut complete_block = BytesMut::new();
    for fragment in fragments {
        complete_block.extend_from_slice(&fragment);
    }

    let mut final_block = complete_block.freeze();
    let decoded_headers = decoder.decode(&mut final_block).unwrap();
    assert_eq!(decoded_headers.len(), headers.len());

    // Verify all headers decoded correctly
    for (expected, actual) in headers.iter().zip(decoded_headers.iter()) {
        assert_eq!(expected.name, actual.name);
        assert_eq!(expected.value, actual.value);
    }
}

/// Test that fragment accumulation respects size limits
#[test]
fn fragment_accumulation_size_limits() {
    let mut stream = Stream::new(7, 65535, 1000); // Small max header list size

    // Start headers
    stream.recv_headers(false, false).unwrap();

    // Add fragment that fits
    let small_fragment = vec![0u8; 2000];
    stream.add_header_fragment(Bytes::from(small_fragment)).unwrap();

    // Add fragment that still fits
    let medium_fragment = vec![0u8; 1500];
    stream.add_header_fragment(Bytes::from(medium_fragment)).unwrap();

    // Try to add fragment that would exceed limit (1000 * 4 = 4000)
    let large_fragment = vec![0u8; 600]; // Total would be 4100 > 4000
    let result = stream.add_header_fragment(Bytes::from(large_fragment));

    assert!(result.is_err());
    let error_msg = format!("{}", result.unwrap_err());
    assert!(error_msg.contains("too large") || error_msg.contains("limit") || error_msg.contains("ENHANCE_YOUR_CALM"));
}

/// Test frame encoding/decoding round-trip for CONTINUATION frames
#[test]
fn continuation_frame_encoding_roundtrip() {
    let test_cases = vec![
        // Basic continuation
        ContinuationFrame {
            stream_id: 1,
            header_block: Bytes::from_static(b"header-data"),
            end_headers: false,
        },
        // Continuation with END_HEADERS
        ContinuationFrame {
            stream_id: 42,
            header_block: Bytes::from_static(b"final-header-data"),
            end_headers: true,
        },
        // Empty continuation
        ContinuationFrame {
            stream_id: 100,
            header_block: Bytes::new(),
            end_headers: true,
        },
        // Large continuation
        ContinuationFrame {
            stream_id: 999,
            header_block: Bytes::from(vec![0x42; 4096]),
            end_headers: false,
        },
    ];

    for original in test_cases {
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        // Parse frame header
        let mut header_bytes = buf.split_to(9);
        let header = FrameHeader::parse(&mut header_bytes).unwrap();

        // Parse continuation frame
        let parsed = ContinuationFrame::parse(&header, buf.freeze()).unwrap();

        // Verify round-trip
        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.header_block, original.header_block);
        assert_eq!(parsed.end_headers, original.end_headers);
    }
}

/// Test that CONTINUATION frames reject stream ID 0
#[test]
fn continuation_frame_rejects_stream_id_zero() {
    let header = FrameHeader {
        length: 4,
        frame_type: 0x9, // CONTINUATION
        flags: 0,
        stream_id: 0, // Invalid for CONTINUATION
    };

    let payload = Bytes::from_static(b"test");
    let result = ContinuationFrame::parse(&header, payload);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("stream ID 0"));
}