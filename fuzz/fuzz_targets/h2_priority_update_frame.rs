//! HTTP/2 PRIORITY_UPDATE frame implementation-gap fuzz target.
//!
//! Tests PRIORITY_UPDATE frame processing per RFC 9218 HTTP/2 Priority specification.
//! PRIORITY_UPDATE frames (type 0x10) update stream priority using urgency and incremental flags.
//!
//! NOTE: PRIORITY_UPDATE frames are not yet implemented in the current HTTP/2 stack,
//! so this fuzzer drives the live frame parser and stream codec implementation gap
//! instead of simulating priority parsing locally.
//!
//! This fuzzer generates arbitrary frame variants and verifies:
//! 1. PRIORITY_UPDATE uses the RFC 9218 HTTP/2 frame type, 0x10
//! 2. The direct parser preserves the extension frame as `Frame::Unknown`
//! 3. The streaming codec skips the unimplemented extension frame and stays aligned
//! 4. Frame size constraints are enforced before extension-frame skipping
//! 5. No panics occur with malformed priority data

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::{
    bytes::{Bytes, BytesMut},
    codec::Decoder,
    http::h2::{
        ErrorCode, Frame, FrameCodec,
        frame::{DEFAULT_MAX_FRAME_SIZE, FrameHeader, parse_frame},
    },
};
use libfuzzer_sys::fuzz_target;

const PRIORITY_UPDATE_FRAME_TYPE: u8 = 0x10;
const PING_FRAME_TYPE: u8 = 0x06;
const MAX_PRIORITY_FIELD_BYTES: usize = 4096;
const MAX_CUSTOM_FIELDS: usize = 10;
const PING_PAYLOAD: &[u8; 8] = b"priority";

/// PRIORITY_UPDATE frame test with arbitrary priority parameters
#[derive(Debug, Clone, Arbitrary)]
struct PriorityUpdateTest {
    /// Prioritized Stream ID carried inside the PRIORITY_UPDATE payload.
    stream_id: u32,
    /// Priority update payload (urgency + incremental + custom fields)
    priority_payload: PriorityPayload,
    /// Additional frame flags beyond standard ones
    extra_flags: u8,
    /// Whether to use the RFC-valid connection stream in the frame header.
    connection_level: bool,
    /// Byte index used when truncating a generated wire frame.
    truncate_seed: u16,
}

/// Priority payload with arbitrary urgency and flags
#[derive(Debug, Clone, Arbitrary)]
struct PriorityPayload {
    /// Urgency level (0-7 valid, >7 should be rejected)
    urgency: u8,
    /// Incremental flag
    incremental: bool,
    /// Additional custom priority fields
    custom_fields: Vec<PriorityField>,
    /// Raw bytes for malformed payloads
    raw_bytes: Vec<u8>,
    /// Whether to use structured or raw format
    use_structured: bool,
}

/// Custom priority field for testing extensions
#[derive(Debug, Clone, Arbitrary)]
struct PriorityField {
    /// Field name (arbitrary string)
    name: String,
    /// Field value (arbitrary string)
    value: String,
}

fuzz_target!(|data: &[u8]| {
    // Guard against excessive input size
    if data.len() > 100_000 {
        return;
    }

    let mut u = Unstructured::new(data);

    // Generate PRIORITY_UPDATE test case
    let test_case = match PriorityUpdateTest::arbitrary(&mut u) {
        Ok(case) => case,
        Err(_) => return,
    };

    // Limit fields to prevent excessive processing
    if test_case.priority_payload.custom_fields.len() > MAX_CUSTOM_FIELDS
        || test_case.priority_payload.raw_bytes.len() > MAX_PRIORITY_FIELD_BYTES
    {
        return;
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observe_direct_priority_update_parser(&test_case);
        observe_codec_skips_complete_priority_update(&test_case);
        observe_codec_alignment_after_priority_update(&test_case);
        observe_truncated_priority_update_waits(&test_case);
        observe_oversized_priority_update_rejected();
    }));

    assert!(
        result.is_ok(),
        "live PRIORITY_UPDATE frame observation should not panic: {test_case:?}",
    );
});

/// Exercise the public frame parser seam. Until PRIORITY_UPDATE has first-class
/// support, the parser must preserve it as an unknown extension frame.
fn observe_direct_priority_update_parser(test_case: &PriorityUpdateTest) {
    let payload = build_priority_update_payload(test_case);
    let header = priority_update_header(test_case, payload.len() as u32);
    let frame = parse_frame(&header, Bytes::copy_from_slice(&payload))
        .expect("PRIORITY_UPDATE extension frame should parse as unknown");

    match frame {
        Frame::Unknown {
            frame_type,
            stream_id,
            payload: parsed_payload,
        } => {
            assert_eq!(frame_type, PRIORITY_UPDATE_FRAME_TYPE);
            assert_eq!(stream_id, header.stream_id);
            assert_eq!(&parsed_payload[..], &payload[..]);
        }
        other => panic!("PRIORITY_UPDATE should parse as Frame::Unknown, got {other:?}"),
    }
}

/// Exercise the streaming codec seam. `FrameCodec` intentionally skips unknown
/// extension frames, so a complete PRIORITY_UPDATE frame alone yields no frame.
fn observe_codec_skips_complete_priority_update(test_case: &PriorityUpdateTest) {
    let payload = build_priority_update_payload(test_case);
    let wire = encode_priority_update_frame(test_case, &payload);
    let mut bytes = BytesMut::from(wire.as_slice());
    let mut codec = FrameCodec::new();

    let decoded = codec
        .decode(&mut bytes)
        .expect("unknown PRIORITY_UPDATE frame should be skipped");
    assert!(
        decoded.is_none(),
        "unimplemented PRIORITY_UPDATE should not yield a decoded frame",
    );
    assert!(
        bytes.is_empty(),
        "complete unknown PRIORITY_UPDATE frame should be consumed",
    );
}

/// After skipping PRIORITY_UPDATE, the codec must keep byte-stream alignment and
/// decode the next known frame.
fn observe_codec_alignment_after_priority_update(test_case: &PriorityUpdateTest) {
    let payload = build_priority_update_payload(test_case);
    let mut wire = encode_priority_update_frame(test_case, &payload);
    wire.extend_from_slice(&encode_ping_frame());

    let mut bytes = BytesMut::from(wire.as_slice());
    let mut codec = FrameCodec::new();
    let decoded = codec
        .decode(&mut bytes)
        .expect("codec should skip PRIORITY_UPDATE and decode following PING");

    assert!(matches!(decoded, Some(Frame::Ping(_))));
    assert!(bytes.is_empty(), "codec should consume the following PING");
}

/// Incomplete PRIORITY_UPDATE bytes should wait for more input rather than
/// panicking or fabricating a frame.
fn observe_truncated_priority_update_waits(test_case: &PriorityUpdateTest) {
    let payload = build_priority_update_payload(test_case);
    let wire = encode_priority_update_frame(test_case, &payload);
    if wire.is_empty() {
        return;
    }

    let max_cut = wire.len().saturating_sub(1);
    let cut = usize::from(test_case.truncate_seed) % (max_cut + 1);
    let mut bytes = BytesMut::from(&wire[..cut]);
    let mut codec = FrameCodec::new();
    let decoded = codec
        .decode(&mut bytes)
        .expect("truncated PRIORITY_UPDATE should wait for more bytes");

    assert!(
        decoded.is_none(),
        "truncated PRIORITY_UPDATE should not decode a frame",
    );
}

/// The codec checks configured frame-size limits before skipping unknown frames.
fn observe_oversized_priority_update_rejected() {
    let wire = encode_frame_header(DEFAULT_MAX_FRAME_SIZE + 1, PRIORITY_UPDATE_FRAME_TYPE, 0, 0);
    let mut bytes = BytesMut::from(wire.as_slice());
    let mut codec = FrameCodec::new();
    let expected_message = format!(
        "frame too large: {} > {DEFAULT_MAX_FRAME_SIZE}",
        DEFAULT_MAX_FRAME_SIZE + 1
    );

    assert_codec_connection_error(
        codec.decode(&mut bytes),
        ErrorCode::FrameSizeError,
        &expected_message,
        "oversized PRIORITY_UPDATE",
    );
    assert!(
        bytes.is_empty(),
        "oversized PRIORITY_UPDATE rejection should consume the parsed frame header"
    );
}

fn assert_codec_connection_error(
    result: Result<Option<Frame>, asupersync::http::h2::H2Error>,
    expected_code: ErrorCode,
    expected_message: &str,
    context: &str,
) {
    let error = result.expect_err("malformed H2 frame should fail at decode boundary");
    assert_eq!(
        error.code, expected_code,
        "{context}: unexpected H2 error code"
    );
    assert_eq!(
        error.message, expected_message,
        "{context}: unexpected H2 error message"
    );
    assert!(
        error.stream_id.is_none(),
        "{context}: codec boundary error should be connection-level: {error:?}"
    );
    assert!(
        error.is_connection_error(),
        "{context}: codec boundary error should classify as connection-level: {error:?}"
    );
    assert_eq!(
        error.to_string(),
        format!("HTTP/2 connection error ({expected_code}): {expected_message}"),
        "{context}: unexpected H2 error display text"
    );
}

/// Build priority payload from structured or raw format
fn build_priority_payload(payload: &PriorityPayload) -> Vec<u8> {
    if !payload.use_structured {
        return payload
            .raw_bytes
            .iter()
            .copied()
            .take(MAX_PRIORITY_FIELD_BYTES)
            .collect();
    }

    // Build structured priority string: "u=N,i=B,field=value,..."
    let mut parts = Vec::new();

    // Add urgency
    parts.push(format!("u={}", payload.urgency));

    // Add incremental flag
    if payload.incremental {
        parts.push("i=1".to_string());
    } else {
        parts.push("i=0".to_string());
    }

    // Add custom fields
    for field in &payload.custom_fields {
        if !field.name.is_empty() && !field.value.is_empty() {
            // Basic sanitization to create testable but potentially invalid syntax
            let sanitized_name = sanitize_field_name(&field.name);
            let sanitized_value = sanitize_field_value(&field.value);
            if !sanitized_name.is_empty() && !sanitized_value.is_empty() {
                parts.push(format!("{}={}", sanitized_name, sanitized_value));
            }
        }
    }

    parts
        .join(",")
        .into_bytes()
        .into_iter()
        .take(MAX_PRIORITY_FIELD_BYTES)
        .collect()
}

fn build_priority_update_payload(test_case: &PriorityUpdateTest) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + MAX_PRIORITY_FIELD_BYTES);
    payload.extend_from_slice(&prioritized_stream_id(test_case).to_be_bytes());
    payload.extend_from_slice(&build_priority_payload(&test_case.priority_payload));
    payload
}

fn prioritized_stream_id(test_case: &PriorityUpdateTest) -> u32 {
    test_case.stream_id & 0x7fff_ffff
}

fn header_stream_id(test_case: &PriorityUpdateTest) -> u32 {
    if test_case.connection_level {
        0
    } else {
        test_case.stream_id.max(1) & 0x7fff_ffff
    }
}

fn priority_update_header(test_case: &PriorityUpdateTest, length: u32) -> FrameHeader {
    FrameHeader {
        length,
        frame_type: PRIORITY_UPDATE_FRAME_TYPE,
        flags: test_case.extra_flags,
        stream_id: header_stream_id(test_case),
    }
}

fn encode_priority_update_frame(test_case: &PriorityUpdateTest, payload: &[u8]) -> Vec<u8> {
    let header = priority_update_header(test_case, payload.len() as u32);
    encode_frame(
        header.length,
        header.frame_type,
        header.flags,
        header.stream_id,
        payload,
    )
}

fn encode_ping_frame() -> Vec<u8> {
    encode_frame(
        PING_PAYLOAD.len() as u32,
        PING_FRAME_TYPE,
        0,
        0,
        PING_PAYLOAD,
    )
}

fn encode_frame(length: u32, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut wire = encode_frame_header(length, frame_type, flags, stream_id);
    wire.extend_from_slice(payload);
    wire
}

fn encode_frame_header(length: u32, frame_type: u8, flags: u8, stream_id: u32) -> Vec<u8> {
    vec![
        (length >> 16) as u8,
        (length >> 8) as u8,
        length as u8,
        frame_type,
        flags,
        ((stream_id >> 24) & 0x7f) as u8,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
    ]
}

/// Sanitize field name for priority string format
fn sanitize_field_name(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        .take(64)
        .collect()
}

/// Sanitize field value for priority string format
fn sanitize_field_value(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c.is_ascii() && c != ',' && c != ';' && c != '\r' && c != '\n')
        .take(256)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_update_frame_type_matches_rfc_9218() {
        assert_eq!(PRIORITY_UPDATE_FRAME_TYPE, 0x10);
    }

    #[test]
    fn direct_parser_preserves_priority_update_as_unknown() {
        observe_direct_priority_update_parser(&structured_case());
    }

    #[test]
    fn codec_skips_priority_update_and_decodes_following_ping() {
        observe_codec_alignment_after_priority_update(&structured_case());
    }

    #[test]
    fn truncated_priority_update_waits_for_more_bytes() {
        observe_truncated_priority_update_waits(&PriorityUpdateTest {
            truncate_seed: 6,
            ..structured_case()
        });
    }

    #[test]
    fn oversized_priority_update_hits_frame_size_guard() {
        observe_oversized_priority_update_rejected();
    }

    fn structured_case() -> PriorityUpdateTest {
        PriorityUpdateTest {
            stream_id: 7,
            priority_payload: PriorityPayload {
                urgency: 3,
                incremental: true,
                custom_fields: vec![PriorityField {
                    name: "custom".to_string(),
                    value: "value".to_string(),
                }],
                raw_bytes: Vec::new(),
                use_structured: true,
            },
            extra_flags: 0,
            connection_level: true,
            truncate_seed: 0,
        }
    }
}
