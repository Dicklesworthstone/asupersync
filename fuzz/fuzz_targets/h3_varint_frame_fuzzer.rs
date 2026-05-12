//! Fuzz target for HTTP/3 varint encoding boundary conditions in frame parsing.
//!
//! Focuses on H3-specific varint usage patterns that differ from raw QUIC varint fuzzing:
//! - Frame type/length varint combinations
//! - Settings ID/value pairs with boundary conditions
//! - Stream ID varints in frame contexts (push_id, quarter_stream_id, etc.)
//! - Malformed varint sequences in frame payloads
//! - Length field mismatches and overflow scenarios
//!
//! Targets the frame parsing logic in src/http/h3_native.rs to find:
//! - Integer overflow in frame length calculations
//! - Inconsistent varint parsing between encode/decode
//! - Edge cases in settings validation
//! - DoS via oversized varint declarations
//!
//! Run with:
//! cargo +nightly fuzz run h3_varint_frame_fuzzer -- -max_total_time=300

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use asupersync::http::h3_native::{
    H3ConnectionConfig, H3EndpointRole, H3Frame, H3NativeError, H3QpackMode, H3Settings,
};
use asupersync::net::quic_core::{QUIC_VARINT_MAX, decode_varint, encode_varint};

const MAX_FRAME_PAYLOAD_SIZE: usize = 16 * 1024; // Prevent memory exhaustion
const MAX_OPERATIONS: usize = 32; // Limit fuzz case complexity

#[derive(Arbitrary, Debug)]
struct H3VarintFuzzInput {
    operations: Vec<H3VarintOperation>,
    attack_mode: AttackMode,
}

#[derive(Arbitrary, Debug, Clone)]
enum H3VarintOperation {
    /// Test frame type varint boundary conditions
    FrameTypeTest {
        frame_type: u64,
        payload_size: u32,
        malform_type: bool,
    },
    /// Test frame length varint edge cases
    FrameLengthTest {
        declared_length: u64,
        actual_payload: Vec<u8>,
    },
    /// Test settings frame with problematic ID/value pairs
    SettingsTest { settings_pairs: Vec<SettingPair> },
    /// Test stream ID varints in frame contexts
    StreamIdTest {
        frame_variant: StreamIdFrameType,
        stream_id: u64,
        extra_payload: Vec<u8>,
    },
    /// Test DATAGRAM quarter_stream_id parsing
    DatagramTest {
        quarter_stream_id: u64,
        payload: Vec<u8>,
        truncate_varint: bool,
    },
    /// Raw malformed frame construction
    MalformedFrame { raw_bytes: Vec<u8> },
}

#[derive(Arbitrary, Debug, Clone)]
struct SettingPair {
    id: u64,
    value: u64,
    corrupt_id: bool,
    corrupt_value: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum StreamIdFrameType {
    CancelPush,
    PushPromise,
    Goaway,
    MaxPushId,
}

#[derive(Arbitrary, Debug, Clone)]
enum AttackMode {
    /// Normal fuzzing
    Normal,
    /// Target varint overflow boundaries
    OverflowFocus,
    /// Target truncation edge cases
    TruncationFocus,
    /// Target length/payload mismatches
    MismatchFocus,
    /// Target settings validation bypasses
    SettingsBypass,
}

fuzz_target!(|input: H3VarintFuzzInput| {
    // Limit operations to prevent timeout
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    let config = H3ConnectionConfig {
        qpack_mode: H3QpackMode::StaticOnly,
        endpoint_role: H3EndpointRole::Client,
        max_frame_payload_size: MAX_FRAME_PAYLOAD_SIZE,
        max_concurrent_request_streams: Some(100),
    };

    let operation_count = input.operations.len() as u64;
    observe_varint_roundtrip_consistency(operation_count, "operation count");
    test_malformed_varint_rejection(operation_count as u8);

    for operation in input.operations {
        execute_h3_varint_operation(&config, operation, &input.attack_mode);
    }
});

fn execute_h3_varint_operation(
    config: &H3ConnectionConfig,
    operation: H3VarintOperation,
    attack_mode: &AttackMode,
) {
    match operation {
        H3VarintOperation::FrameTypeTest {
            frame_type,
            payload_size,
            malform_type,
        } => {
            test_frame_type_varint(config, frame_type, payload_size, malform_type, attack_mode);
        }

        H3VarintOperation::FrameLengthTest {
            declared_length,
            actual_payload,
        } => {
            test_frame_length_mismatch(config, declared_length, &actual_payload);
        }

        H3VarintOperation::SettingsTest { settings_pairs } => {
            test_settings_varint_pairs(config, &settings_pairs, attack_mode);
        }

        H3VarintOperation::StreamIdTest {
            frame_variant,
            stream_id,
            extra_payload,
        } => {
            test_stream_id_varint(config, frame_variant, stream_id, &extra_payload);
        }

        H3VarintOperation::DatagramTest {
            quarter_stream_id,
            payload,
            truncate_varint,
        } => {
            test_datagram_quarter_stream_id(config, quarter_stream_id, &payload, truncate_varint);
        }

        H3VarintOperation::MalformedFrame { raw_bytes } => {
            test_raw_malformed_frame(config, &raw_bytes);
        }
    }
}

fn test_frame_type_varint(
    config: &H3ConnectionConfig,
    frame_type: u64,
    payload_size: u32,
    malform_type: bool,
    attack_mode: &AttackMode,
) {
    let mut buf = Vec::new();

    // Apply attack mode modifications
    let effective_frame_type = match attack_mode {
        AttackMode::OverflowFocus => frame_type.saturating_add(QUIC_VARINT_MAX),
        _ => frame_type,
    };

    if malform_type {
        // Manually construct malformed varint for frame type
        buf.push(0xFF); // Invalid varint prefix
        buf.push(0xFF);
        buf.push(0xFF);
        buf.push(0xFF);
        buf.push(effective_frame_type as u8);
    } else {
        // Use proper encoding but with potentially problematic value
        if !observe_encode_varint(effective_frame_type, &mut buf, "frame type") {
            return;
        }
    }

    // Add frame length and dummy payload
    let limited_payload_size = (payload_size as usize).min(MAX_FRAME_PAYLOAD_SIZE);
    assert!(observe_encode_varint(
        limited_payload_size as u64,
        &mut buf,
        "frame payload length"
    ));
    buf.resize(buf.len() + limited_payload_size, 0x41);

    // Test decoding - should not panic
    observe_h3_frame_decode(&buf, config, "frame type test");
}

fn test_frame_length_mismatch(
    config: &H3ConnectionConfig,
    declared_length: u64,
    actual_payload: &[u8],
) {
    let mut buf = Vec::new();

    // Use DATA frame (type 0x0) as a simple test case
    assert!(observe_encode_varint(0x0, &mut buf, "data frame type"));

    // Encode declared length (potentially mismatched)
    if !observe_encode_varint(declared_length, &mut buf, "declared frame length") {
        return;
    }

    // Add actual payload (may not match declared length)
    let limited_payload = if actual_payload.len() > MAX_FRAME_PAYLOAD_SIZE {
        &actual_payload[..MAX_FRAME_PAYLOAD_SIZE]
    } else {
        actual_payload
    };
    buf.extend_from_slice(limited_payload);

    // Test decoding - should handle length mismatches gracefully
    observe_h3_frame_decode(&buf, config, "frame length mismatch");
}

fn test_settings_varint_pairs(
    config: &H3ConnectionConfig,
    settings_pairs: &[SettingPair],
    attack_mode: &AttackMode,
) {
    let mut buf = Vec::new();

    // SETTINGS frame type (0x4)
    assert!(observe_encode_varint(0x4, &mut buf, "settings frame type"));

    let mut payload = Vec::new();
    for (i, pair) in settings_pairs.iter().enumerate() {
        if i > 50 {
            break; // Limit to prevent memory exhaustion
        }

        let effective_id = match attack_mode {
            AttackMode::SettingsBypass => {
                // Target HTTP/2 reserved IDs that should be rejected
                match pair.id % 6 {
                    0 => 0x00, // Reserved
                    1 => 0x02, // Reserved
                    2 => 0x03, // Reserved
                    3 => 0x04, // Reserved
                    4 => 0x05, // Reserved
                    _ => pair.id,
                }
            }
            AttackMode::OverflowFocus => pair.id.saturating_add(QUIC_VARINT_MAX / 2),
            _ => pair.id,
        };

        if pair.corrupt_id {
            // Manually add malformed varint for setting ID
            payload.push(0x80); // Start of 2-byte varint but truncated
        } else {
            if !observe_encode_varint(effective_id, &mut payload, "settings id") {
                return;
            }
        }

        if pair.corrupt_value {
            // Manually add malformed varint for setting value
            payload.push(0xC0); // Start of 4-byte varint but truncated
            payload.push(0xFF);
        } else {
            if !observe_encode_varint(pair.value, &mut payload, "settings value") {
                return;
            }
        }
    }

    // Encode payload length
    assert!(observe_encode_varint(
        payload.len() as u64,
        &mut buf,
        "settings payload length"
    ));
    buf.extend_from_slice(&payload);

    // Test both raw settings parsing and frame parsing
    observe_h3_settings_decode(&payload, "settings payload");
    observe_h3_frame_decode(&buf, config, "settings frame");
}

fn test_stream_id_varint(
    config: &H3ConnectionConfig,
    frame_variant: StreamIdFrameType,
    stream_id: u64,
    extra_payload: &[u8],
) {
    let mut buf = Vec::new();

    let frame_type = match frame_variant {
        StreamIdFrameType::CancelPush => 0x3,
        StreamIdFrameType::PushPromise => 0x5,
        StreamIdFrameType::Goaway => 0x7,
        StreamIdFrameType::MaxPushId => 0xD,
    };

    assert!(observe_encode_varint(
        frame_type,
        &mut buf,
        "stream-id frame type"
    ));

    let mut payload = Vec::new();
    if !observe_encode_varint(stream_id, &mut payload, "stream id payload") {
        return;
    }

    // Add extra payload for PushPromise (requires field block)
    if matches!(frame_variant, StreamIdFrameType::PushPromise) {
        let limited_extra = if extra_payload.len() > MAX_FRAME_PAYLOAD_SIZE / 2 {
            &extra_payload[..MAX_FRAME_PAYLOAD_SIZE / 2]
        } else {
            extra_payload
        };
        payload.extend_from_slice(limited_extra);
    }

    assert!(observe_encode_varint(
        payload.len() as u64,
        &mut buf,
        "stream-id payload length"
    ));
    buf.extend_from_slice(&payload);

    // Test decoding
    observe_h3_frame_decode(&buf, config, "stream-id frame");
}

fn test_datagram_quarter_stream_id(
    config: &H3ConnectionConfig,
    quarter_stream_id: u64,
    payload: &[u8],
    truncate_varint: bool,
) {
    let mut buf = Vec::new();

    // DATAGRAM frame type (0x30)
    assert!(observe_encode_varint(0x30, &mut buf, "datagram frame type"));

    let mut frame_payload = Vec::new();

    if truncate_varint {
        // Create truncated varint for quarter_stream_id
        frame_payload.push(0x80); // Start of multi-byte varint but incomplete
    } else {
        if !observe_encode_varint(
            quarter_stream_id,
            &mut frame_payload,
            "datagram quarter stream id",
        ) {
            return;
        }
    }

    // Add datagram payload
    let limited_payload = if payload.len() > MAX_FRAME_PAYLOAD_SIZE / 2 {
        &payload[..MAX_FRAME_PAYLOAD_SIZE / 2]
    } else {
        payload
    };
    frame_payload.extend_from_slice(limited_payload);

    assert!(observe_encode_varint(
        frame_payload.len() as u64,
        &mut buf,
        "datagram payload length"
    ));
    buf.extend_from_slice(&frame_payload);

    // Test decoding
    observe_h3_frame_decode(&buf, config, "datagram frame");
}

fn test_raw_malformed_frame(config: &H3ConnectionConfig, raw_bytes: &[u8]) {
    // Test completely arbitrary byte sequences to catch parsing edge cases
    let limited_bytes = if raw_bytes.len() > MAX_FRAME_PAYLOAD_SIZE {
        &raw_bytes[..MAX_FRAME_PAYLOAD_SIZE]
    } else {
        raw_bytes
    };

    observe_h3_frame_decode(limited_bytes, config, "raw malformed frame");
}

/// Test varint roundtrip consistency in H3 context
fn observe_varint_roundtrip_consistency(value: u64, context: &str) {
    let mut buf = Vec::new();
    if !observe_encode_varint(value, &mut buf, context) {
        return;
    }

    match decode_varint(&buf) {
        Ok((decoded, len)) => {
            // Should decode to same value and consume entire buffer
            assert_eq!(decoded, value, "{context}: decoded value mismatch");
            assert_eq!(len, buf.len(), "{context}: decoder left encoded bytes");
        }
        Err(error) => panic!("{context}: decode failed after successful encode: {error:?}"),
    }
}

/// Test that malformed varint prefixes are rejected consistently
fn test_malformed_varint_rejection(first_byte: u8) {
    let malformed_sequences = [
        vec![first_byte],                   // Single byte with invalid pattern
        vec![first_byte, 0xFF],             // Two bytes
        vec![first_byte, 0xFF, 0xFF],       // Three bytes
        vec![first_byte, 0xFF, 0xFF, 0xFF], // Four bytes
    ];

    for seq in &malformed_sequences {
        match decode_varint(seq) {
            Ok((decoded, len)) => {
                assert!(
                    matches!(len, 1 | 2 | 4 | 8),
                    "malformed-prefix probe decoded with invalid varint length {len}"
                );
                assert!(
                    len <= seq.len(),
                    "malformed-prefix probe consumed past input length"
                );
                observe_varint_roundtrip_consistency(decoded, "malformed-prefix decoded value");
            }
            Err(_) => {
                assert!(
                    seq.len() < expected_varint_len(seq[0]),
                    "varint decoder rejected a complete malformed-prefix probe"
                );
            }
        }
    }
}

fn observe_encode_varint(value: u64, out: &mut Vec<u8>, context: &str) -> bool {
    let before_len = out.len();
    match encode_varint(value, out) {
        Ok(()) => {
            let written = out.len() - before_len;
            assert_eq!(
                written,
                expected_varint_len(out[before_len]),
                "{context}: encoded varint length did not match prefix bits"
            );
            assert!(
                matches!(written, 1 | 2 | 4 | 8),
                "{context}: encoded invalid varint length {written}"
            );

            let encoded = &out[before_len..];
            match decode_varint(encoded) {
                Ok((decoded, consumed)) => {
                    assert_eq!(
                        decoded, value,
                        "{context}: encoded varint roundtrip mismatch"
                    );
                    assert_eq!(
                        consumed, written,
                        "{context}: decoded varint consumed unexpected byte count"
                    );
                }
                Err(error) => panic!("{context}: encoded varint failed to decode: {error:?}"),
            }
            true
        }
        Err(_) => {
            assert_eq!(
                out.len(),
                before_len,
                "{context}: failed varint encode mutated output"
            );
            assert!(
                value > QUIC_VARINT_MAX,
                "{context}: encode rejected in-range varint value {value}"
            );
            false
        }
    }
}

fn expected_varint_len(first_byte: u8) -> usize {
    match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

fn observe_h3_frame_decode(input: &[u8], config: &H3ConnectionConfig, context: &str) {
    match H3Frame::decode(input, config) {
        Ok((_, consumed)) => {
            assert!(consumed > 0, "{context}: decoded frame consumed no bytes");
            assert!(
                consumed <= input.len(),
                "{context}: decoded frame consumed past input length"
            );
        }
        Err(error) => observe_h3_error(&error, context),
    }
}

fn observe_h3_settings_decode(payload: &[u8], context: &str) {
    match H3Settings::decode_payload(payload) {
        Ok(settings) => {
            let mut encoded = Vec::new();
            match settings.encode_payload(&mut encoded) {
                Ok(()) => {}
                Err(error) => panic!("{context}: decoded settings failed to re-encode: {error:?}"),
            }
        }
        Err(error) => observe_h3_error(&error, context),
    }
}

fn observe_h3_error(error: &H3NativeError, context: &str) {
    match error {
        H3NativeError::FrameTooLarge {
            payload_size,
            max_size,
        } => assert!(
            payload_size > max_size,
            "{context}: FrameTooLarge without oversized payload"
        ),
        H3NativeError::ConcurrentStreamLimitExceeded { active, limit } => assert!(
            active >= limit,
            "{context}: stream limit error without an exhausted limit"
        ),
        H3NativeError::UnexpectedEof
        | H3NativeError::InvalidFrame(_)
        | H3NativeError::DuplicateSetting(_)
        | H3NativeError::InvalidSettingValue(_)
        | H3NativeError::ControlProtocol(_)
        | H3NativeError::StreamProtocol(_)
        | H3NativeError::QpackPolicy(_)
        | H3NativeError::InvalidRequestPseudoHeader(_)
        | H3NativeError::InvalidResponsePseudoHeader(_) => {}
    }
}
