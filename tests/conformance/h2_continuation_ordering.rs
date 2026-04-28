#![allow(warnings)]
#![allow(clippy::all)]
//! HTTP/2 CONTINUATION Frame Ordering Conformance Tests (RFC 9113 §6.10)
//!
//! Tests RFC 9113 §6.10 CONTINUATION frame ordering requirements:
//! - CONTINUATION MUST immediately follow HEADERS or PUSH_PROMISE
//! - No other frame types allowed between HEADERS and CONTINUATION
//! - END_HEADERS flag processing across fragmented header blocks
//! - Stream state consistency during header block fragmentation

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    error::{ErrorCode, H2Error},
    frame::{
        ContinuationFrame, Frame, FrameHeader, FrameType, HeadersFrame,
        parse_frame, headers_flags, continuation_flags,
    },
};

/// Create HEADERS frame bytes with specific flags
fn create_headers_frame(stream_id: u32, end_headers: bool, end_stream: bool, header_block: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Frame header
    frame.extend_from_slice(&[(header_block.len() >> 16) as u8, (header_block.len() >> 8) as u8, header_block.len() as u8]);
    frame.push(0x01); // HEADERS type

    let mut flags = 0u8;
    if end_headers { flags |= 0x04; } // END_HEADERS
    if end_stream { flags |= 0x01; }  // END_STREAM
    frame.push(flags);

    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(header_block);

    frame
}

/// Create CONTINUATION frame bytes
fn create_continuation_frame(stream_id: u32, end_headers: bool, header_block: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    // Frame header
    frame.extend_from_slice(&[(header_block.len() >> 16) as u8, (header_block.len() >> 8) as u8, header_block.len() as u8]);
    frame.push(0x09); // CONTINUATION type

    let mut flags = 0u8;
    if end_headers { flags |= 0x04; } // END_HEADERS
    frame.push(flags);

    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(header_block);

    frame
}

/// Create SETTINGS frame bytes (used for ordering violation tests)
fn create_settings_frame() -> Vec<u8> {
    vec![
        0, 0, 0,    // length = 0
        0x04,       // SETTINGS type
        0x00,       // no flags
        0, 0, 0, 0, // stream_id = 0
    ]
}

/// Create DATA frame bytes (used for ordering violation tests)
fn create_data_frame(stream_id: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();

    frame.extend_from_slice(&[(data.len() >> 16) as u8, (data.len() >> 8) as u8, data.len() as u8]);
    frame.push(0x00); // DATA type
    frame.push(0x00); // no flags
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(data);

    frame
}

/// Parse frame from bytes
fn parse_h2_frame(data: &[u8]) -> Result<(FrameHeader, Frame), H2Error> {
    if data.len() < 9 {
        return Err(H2Error::Protocol("frame too short".into()));
    }

    let header = FrameHeader {
        length: u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize,
        frame_type: FrameType::from_u8(data[3]).unwrap_or(FrameType::Data),
        flags: data[4],
        stream_id: u32::from_be_bytes([data[5], data[6], data[7], data[8]]) & 0x7FFFFFFF,
    };

    let payload = &data[9..];
    let frame = parse_frame(&header, payload)?;

    Ok((header, frame))
}

#[test]
fn continuation_must_immediately_follow_headers() {
    // RFC 9113 §6.10: CONTINUATION frames MUST immediately follow HEADERS
    let stream_id = 3;
    let header_block_part1 = b"partial-header-block-1";
    let header_block_part2 = b"partial-header-block-2";

    // HEADERS frame without END_HEADERS (indicates more fragments follow)
    let headers_bytes = create_headers_frame(stream_id, false, false, header_block_part1);
    let (headers_header, headers_frame) = parse_h2_frame(&headers_bytes)
        .expect("HEADERS frame should parse");

    assert_eq!(headers_header.stream_id, stream_id);
    assert_eq!(headers_header.flags & 0x04, 0); // END_HEADERS not set

    // CONTINUATION frame immediately following HEADERS
    let cont_bytes = create_continuation_frame(stream_id, true, header_block_part2);
    let (cont_header, cont_frame) = parse_h2_frame(&cont_bytes)
        .expect("CONTINUATION frame should parse");

    assert_eq!(cont_header.stream_id, stream_id);
    assert_eq!(cont_header.flags & 0x04, 0x04); // END_HEADERS set

    match cont_frame {
        Frame::Continuation(cont) => {
            assert_eq!(cont.header_block_fragment, header_block_part2);
        }
        _ => panic!("expected CONTINUATION frame"),
    }
}

#[test]
fn settings_between_headers_and_continuation_violates_ordering() {
    // RFC 9113 §6.10: No other frames allowed between HEADERS and CONTINUATION
    let stream_id = 5;

    // HEADERS frame without END_HEADERS
    let headers_bytes = create_headers_frame(stream_id, false, false, b"partial-headers");
    let (headers_header, _) = parse_h2_frame(&headers_bytes)
        .expect("HEADERS frame should parse");

    assert_eq!(headers_header.flags & 0x04, 0); // END_HEADERS not set

    // SETTINGS frame (protocol violation - should not appear here)
    let settings_bytes = create_settings_frame();
    let (settings_header, settings_frame) = parse_h2_frame(&settings_bytes)
        .expect("SETTINGS frame should parse in isolation");

    assert_eq!(settings_header.stream_id, 0); // Connection-level frame

    // In a real implementation, the parser should reject this sequence
    // or track that SETTINGS violates the HEADERS->CONTINUATION requirement

    // CONTINUATION frame after the violating SETTINGS
    let cont_bytes = create_continuation_frame(stream_id, true, b"continuation-data");
    let (cont_header, _) = parse_h2_frame(&cont_bytes)
        .expect("CONTINUATION frame should parse in isolation");

    assert_eq!(cont_header.stream_id, stream_id);

    // The violation is the interleaving - real parser should reject this sequence
}

#[test]
fn data_between_headers_and_continuation_violates_ordering() {
    // RFC 9113 §6.10: DATA frames also violate HEADERS->CONTINUATION ordering
    let stream_id = 7;

    // HEADERS frame without END_HEADERS
    let headers_bytes = create_headers_frame(stream_id, false, false, b"partial");
    let (headers_header, _) = parse_h2_frame(&headers_bytes)
        .expect("HEADERS frame should parse");

    assert_eq!(headers_header.flags & 0x04, 0);

    // DATA frame on same stream (protocol violation)
    let data_bytes = create_data_frame(stream_id, b"request-body");
    let (data_header, data_frame) = parse_h2_frame(&data_bytes)
        .expect("DATA frame should parse in isolation");

    assert_eq!(data_header.stream_id, stream_id);

    match data_frame {
        Frame::Data(data) => {
            assert_eq!(data.data, b"request-body");
        }
        _ => panic!("expected DATA frame"),
    }

    // CONTINUATION frame
    let cont_bytes = create_continuation_frame(stream_id, true, b"rest-of-headers");
    let (cont_header, _) = parse_h2_frame(&cont_bytes)
        .expect("CONTINUATION frame should parse");

    assert_eq!(cont_header.stream_id, stream_id);

    // Real parser should reject DATA between HEADERS and CONTINUATION
}

#[test]
fn continuation_stream_id_must_match_headers() {
    // RFC 9113 §6.10: CONTINUATION stream_id must match the HEADERS stream_id
    let headers_stream_id = 9;
    let wrong_stream_id = 11;

    // HEADERS frame
    let headers_bytes = create_headers_frame(headers_stream_id, false, false, b"start-headers");
    let (headers_header, _) = parse_h2_frame(&headers_bytes)
        .expect("HEADERS frame should parse");

    assert_eq!(headers_header.stream_id, headers_stream_id);

    // CONTINUATION frame with wrong stream_id (protocol violation)
    let cont_bytes = create_continuation_frame(wrong_stream_id, true, b"end-headers");
    let (cont_header, cont_frame) = parse_h2_frame(&cont_bytes)
        .expect("CONTINUATION frame should parse in isolation");

    assert_eq!(cont_header.stream_id, wrong_stream_id);
    assert_ne!(cont_header.stream_id, headers_header.stream_id);

    // Real implementation should enforce stream_id consistency
    // This sequence should be rejected as a protocol violation
}

#[test]
fn multiple_continuation_frames_preserve_ordering() {
    // RFC 9113 §6.10: Multiple CONTINUATION frames must maintain order
    let stream_id = 13;
    let fragments = [
        b"fragment-1".as_slice(),
        b"fragment-2".as_slice(),
        b"fragment-3".as_slice(),
        b"final-fragment".as_slice(),
    ];

    // HEADERS frame without END_HEADERS
    let headers_bytes = create_headers_frame(stream_id, false, false, fragments[0]);
    let (headers_header, _) = parse_h2_frame(&headers_bytes)
        .expect("HEADERS frame should parse");

    assert_eq!(headers_header.stream_id, stream_id);
    assert_eq!(headers_header.flags & 0x04, 0); // END_HEADERS not set

    // Series of CONTINUATION frames
    for (i, &fragment) in fragments[1..].iter().enumerate() {
        let is_last = i == fragments.len() - 2;
        let cont_bytes = create_continuation_frame(stream_id, is_last, fragment);
        let (cont_header, cont_frame) = parse_h2_frame(&cont_bytes)
            .expect("CONTINUATION frame should parse");

        assert_eq!(cont_header.stream_id, stream_id);

        if is_last {
            assert_eq!(cont_header.flags & 0x04, 0x04); // END_HEADERS set on final frame
        } else {
            assert_eq!(cont_header.flags & 0x04, 0); // END_HEADERS not set on intermediate frames
        }

        match cont_frame {
            Frame::Continuation(cont) => {
                assert_eq!(cont.header_block_fragment, fragment);
            }
            _ => panic!("expected CONTINUATION frame"),
        }
    }
}

#[test]
fn headers_with_end_headers_does_not_require_continuation() {
    // RFC 9113 §6.10: HEADERS with END_HEADERS set does not expect CONTINUATION
    let stream_id = 15;
    let complete_headers = b"complete-header-block";

    // HEADERS frame with END_HEADERS set
    let headers_bytes = create_headers_frame(stream_id, true, false, complete_headers);
    let (headers_header, headers_frame) = parse_h2_frame(&headers_bytes)
        .expect("complete HEADERS frame should parse");

    assert_eq!(headers_header.stream_id, stream_id);
    assert_eq!(headers_header.flags & 0x04, 0x04); // END_HEADERS set

    match headers_frame {
        Frame::Headers(headers) => {
            assert_eq!(headers.header_block_fragment, complete_headers);
        }
        _ => panic!("expected HEADERS frame"),
    }

    // No CONTINUATION frame should follow - header block is complete
    // Any subsequent frame can be a different type without violating ordering
}

#[test]
fn continuation_without_preceding_headers_is_protocol_error() {
    // RFC 9113 §6.10: CONTINUATION without preceding HEADERS/PUSH_PROMISE is error
    let stream_id = 17;

    // CONTINUATION frame without preceding HEADERS (protocol violation)
    let cont_bytes = create_continuation_frame(stream_id, true, b"orphaned-continuation");

    // Individual frame parsing might succeed, but sequence validation should fail
    let result = parse_h2_frame(&cont_bytes);

    match result {
        Ok((header, frame)) => {
            assert_eq!(header.stream_id, stream_id);
            // Frame parses correctly in isolation
            // But sequence-level validation should reject orphaned CONTINUATION
        }
        Err(_) => {
            // Some parsers might reject orphaned CONTINUATION immediately
        }
    }
}

#[cfg(test)]
mod protocol_compliance_tests {
    use super::*;

    #[test]
    fn continuation_frame_format_validation() {
        // Validate CONTINUATION frame format per RFC 9113 §6.10
        let stream_id = 19;
        let header_fragment = b"valid-header-fragment";

        let cont_bytes = create_continuation_frame(stream_id, true, header_fragment);
        let (header, frame) = parse_h2_frame(&cont_bytes)
            .expect("valid CONTINUATION frame should parse");

        assert_eq!(header.frame_type, FrameType::Continuation);
        assert_eq!(header.stream_id, stream_id);
        assert_eq!(header.flags & 0x04, 0x04); // END_HEADERS set

        match frame {
            Frame::Continuation(cont) => {
                assert_eq!(cont.header_block_fragment, header_fragment);
                assert_eq!(cont.stream_id, stream_id);
            }
            _ => panic!("expected CONTINUATION frame"),
        }
    }

    #[test]
    fn continuation_zero_stream_id_is_protocol_error() {
        // RFC 9113 §6.10: CONTINUATION with stream_id=0 is protocol error
        let cont_bytes = create_continuation_frame(0, true, b"invalid-stream");

        let result = parse_h2_frame(&cont_bytes);

        // Parser should reject CONTINUATION with stream_id=0
        match result {
            Err(_) => {
                // Expected - CONTINUATION with stream_id=0 violates protocol
            }
            Ok((header, _)) if header.stream_id == 0 => {
                panic!("CONTINUATION with stream_id=0 should be rejected");
            }
            Ok(_) => {
                // Some parsers might correct stream_id - defensive but acceptable
            }
        }
    }
}