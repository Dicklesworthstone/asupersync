//! Property tests for WebSocket frame codec (RFC 6455).
//!
//! Verifies mask involution, encode/decode round-trips across all payload length
//! encodings, control frame constraints, and opcode parsing.

mod common;

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::codec::{Decoder, Encoder};
use asupersync::net::websocket::{apply_mask, CloseCode, Frame, FrameCodec, Opcode, WsError};
use common::{init_test_logging, test_proptest_config};
use proptest::prelude::*;

// ============================================================================
// Arbitrary Generators
// ============================================================================

fn arb_mask_key() -> impl Strategy<Value = [u8; 4]> {
    any::<[u8; 4]>()
}

fn arb_payload_small() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=125)
}

fn arb_payload_medium() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 126..=1024)
}

fn arb_payload_any() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=4096)
}

fn arb_valid_opcode_byte() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(0x0u8),
        Just(0x1),
        Just(0x2),
        Just(0x8),
        Just(0x9),
        Just(0xA),
    ]
}

fn arb_invalid_opcode_byte() -> impl Strategy<Value = u8> {
    prop_oneof![3u8..=7u8, 0x0Bu8..=0x0Fu8,]
}

fn arb_data_opcode() -> impl Strategy<Value = Opcode> {
    prop_oneof![Just(Opcode::Text), Just(Opcode::Binary),]
}

// ============================================================================
// Mask Involution: apply_mask(apply_mask(data, key), key) == data
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(500))]

    /// XOR masking is self-inverse (involution).
    #[test]
    fn mask_is_involution(data in arb_payload_any(), key in arb_mask_key()) {
        init_test_logging();
        let original = data.clone();
        let mut buf = data;
        apply_mask(&mut buf, key);
        apply_mask(&mut buf, key);
        prop_assert_eq!(buf, original, "double masking must yield original data");
    }

    /// Masking with zero key is identity.
    #[test]
    fn mask_zero_key_is_identity(data in arb_payload_any()) {
        init_test_logging();
        let original = data.clone();
        let mut buf = data;
        apply_mask(&mut buf, [0, 0, 0, 0]);
        prop_assert_eq!(buf, original, "zero mask key should be identity");
    }

    /// Masking empty payload is always empty.
    #[test]
    fn mask_empty_payload(key in arb_mask_key()) {
        init_test_logging();
        let mut buf: Vec<u8> = vec![];
        apply_mask(&mut buf, key);
        prop_assert!(buf.is_empty());
    }
}

// ============================================================================
// Encode/Decode Round-Trip (Client → Server)
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(300))]

    /// Client-encoded text frames decode correctly on server.
    #[test]
    fn roundtrip_client_to_server_text(payload in arb_payload_any()) {
        init_test_logging();
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::text(Bytes::from(payload.clone()));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert!(parsed.fin);
        prop_assert_eq!(parsed.opcode, Opcode::Text);
        prop_assert_eq!(parsed.payload.as_ref(), payload.as_slice());
    }

    /// Client-encoded binary frames decode correctly on server.
    #[test]
    fn roundtrip_client_to_server_binary(payload in arb_payload_any()) {
        init_test_logging();
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::binary(Bytes::from(payload.clone()));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert!(parsed.fin);
        prop_assert_eq!(parsed.opcode, Opcode::Binary);
        prop_assert_eq!(parsed.payload.as_ref(), payload.as_slice());
    }

    /// Server-encoded text frames decode correctly on client.
    #[test]
    fn roundtrip_server_to_client_text(payload in arb_payload_any()) {
        init_test_logging();
        let mut encoder = FrameCodec::server();
        let mut decoder = FrameCodec::client();
        let frame = Frame::text(Bytes::from(payload.clone()));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert!(parsed.fin);
        prop_assert_eq!(parsed.opcode, Opcode::Text);
        prop_assert_eq!(parsed.payload.as_ref(), payload.as_slice());
    }
}

// ============================================================================
// Payload Length Encoding Boundaries
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Small payloads (0-125 bytes) use 7-bit length encoding.
    #[test]
    fn payload_length_7bit(payload in arb_payload_small()) {
        init_test_logging();
        let mut encoder = FrameCodec::server();
        let mut decoder = FrameCodec::client();
        let len = payload.len();
        let frame = Frame::binary(Bytes::from(payload));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // For server (unmasked): header is 2 bytes + payload
        prop_assert!(buf.len() == 2 + len, "7-bit length: expected 2 + {} bytes, got {}", len, buf.len());

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(parsed.payload.len(), len);
    }

    /// Medium payloads (126-65535 bytes) use 16-bit length encoding.
    #[test]
    fn payload_length_16bit(payload in arb_payload_medium()) {
        init_test_logging();
        let mut encoder = FrameCodec::server();
        let mut decoder = FrameCodec::client();
        let len = payload.len();
        let frame = Frame::binary(Bytes::from(payload));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // For server (unmasked): header is 2 + 2 (extended length) + payload
        prop_assert!(buf.len() == 4 + len, "16-bit length: expected 4 + {} bytes, got {}", len, buf.len());

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert_eq!(parsed.payload.len(), len);
    }
}

// ============================================================================
// Control Frame Constraints
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Ping frames with valid payloads (≤125 bytes) round-trip correctly.
    #[test]
    fn ping_roundtrip(payload in arb_payload_small()) {
        init_test_logging();
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::ping(Bytes::from(payload.clone()));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert!(parsed.fin);
        prop_assert_eq!(parsed.opcode, Opcode::Ping);
        prop_assert_eq!(parsed.payload.as_ref(), payload.as_slice());
    }

    /// Pong frames with valid payloads (≤125 bytes) round-trip correctly.
    #[test]
    fn pong_roundtrip(payload in arb_payload_small()) {
        init_test_logging();
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::pong(Bytes::from(payload.clone()));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert!(parsed.fin);
        prop_assert_eq!(parsed.opcode, Opcode::Pong);
        prop_assert_eq!(parsed.payload.as_ref(), payload.as_slice());
    }

    /// Control frames with payload > 125 bytes are rejected at encode time.
    #[test]
    fn control_frame_rejects_large_payload(
        extra in 1usize..=200,
    ) {
        init_test_logging();
        let payload = vec![0u8; 125 + extra];
        let mut frame = Frame::ping(Bytes::new());
        frame.payload = Bytes::from(payload);

        let mut codec = FrameCodec::server();
        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);
        prop_assert!(
            matches!(result, Err(WsError::ControlFrameTooLarge(_))),
            "control frame with {} bytes should be rejected", 125 + extra
        );
    }

    /// Fragmented control frames are rejected at encode time.
    #[test]
    fn fragmented_control_rejected(payload in arb_payload_small()) {
        init_test_logging();
        let mut frame = Frame::ping(Bytes::from(payload));
        frame.fin = false;

        let mut codec = FrameCodec::server();
        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);
        prop_assert!(
            matches!(result, Err(WsError::FragmentedControlFrame)),
            "fragmented control frame should be rejected"
        );
    }
}

// ============================================================================
// Opcode Parsing
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Valid opcode bytes parse successfully.
    #[test]
    fn opcode_valid_roundtrip(byte in arb_valid_opcode_byte()) {
        init_test_logging();
        let opcode = Opcode::from_u8(byte).unwrap();
        prop_assert_eq!(opcode as u8, byte);
    }

    /// Invalid opcode bytes are rejected.
    #[test]
    fn opcode_invalid_rejected(byte in arb_invalid_opcode_byte()) {
        init_test_logging();
        let result = Opcode::from_u8(byte);
        prop_assert!(
            matches!(result, Err(WsError::InvalidOpcode(v)) if v == byte),
            "invalid opcode 0x{byte:02x} should be rejected"
        );
    }
}

// ============================================================================
// Close Frame Encoding
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Close frames with code and short reason round-trip correctly.
    #[test]
    fn close_frame_roundtrip(
        code in 1000u16..=4999,
        reason in "[a-zA-Z0-9 ]{0,50}",
    ) {
        init_test_logging();
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let frame = Frame::close(Some(code), Some(&reason));

        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        let parsed = decoder.decode(&mut buf).unwrap().unwrap();
        prop_assert!(parsed.fin);
        prop_assert_eq!(parsed.opcode, Opcode::Close);

        // Verify payload structure: 2-byte code + reason
        let payload = parsed.payload;
        prop_assert!(payload.len() >= 2);
        let parsed_code = u16::from_be_bytes([payload[0], payload[1]]);
        prop_assert_eq!(parsed_code, code);
        let parsed_reason = std::str::from_utf8(&payload[2..]).unwrap();
        prop_assert_eq!(parsed_reason, reason.as_str());
    }

    /// Close frames with code only (no reason) have exactly 2-byte payload.
    #[test]
    fn close_frame_code_only(code in 1000u16..=4999) {
        init_test_logging();
        let frame = Frame::close(Some(code), None);
        prop_assert_eq!(frame.payload.len(), 2);
        let parsed_code = u16::from_be_bytes([frame.payload[0], frame.payload[1]]);
        prop_assert_eq!(parsed_code, code);
    }
}

// ============================================================================
// CloseCode Sendability
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(50))]

    /// Non-sendable close codes are exactly the three specified by RFC 6455.
    #[test]
    fn close_code_sendability(_dummy in 0u8..1) {
        init_test_logging();
        let non_sendable: [CloseCode; 3] = [
            CloseCode::NoStatusReceived,
            CloseCode::Abnormal,
            CloseCode::TlsHandshake,
        ];
        let sendable: [CloseCode; 10] = [
            CloseCode::Normal,
            CloseCode::GoingAway,
            CloseCode::ProtocolError,
            CloseCode::Unsupported,
            CloseCode::Reserved,
            CloseCode::InvalidPayload,
            CloseCode::PolicyViolation,
            CloseCode::MessageTooBig,
            CloseCode::MandatoryExtension,
            CloseCode::InternalError,
        ];

        for code in non_sendable {
            prop_assert!(!code.is_sendable(), "{code:?} should not be sendable");
        }
        for code in sendable {
            prop_assert!(code.is_sendable(), "{code:?} should be sendable");
        }
    }
}

// ============================================================================
// Client Masking Invariants
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(200))]

    /// Client-encoded frames always have the mask bit set in the wire format.
    #[test]
    fn client_frames_are_masked(payload in arb_payload_any(), opcode in arb_data_opcode()) {
        init_test_logging();
        let frame = match opcode {
            Opcode::Text => Frame::text(Bytes::from(payload)),
            Opcode::Binary => Frame::binary(Bytes::from(payload)),
            _ => unreachable!(),
        };

        let mut encoder = FrameCodec::client();
        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // Second byte's high bit is the MASK flag
        prop_assert!(
            buf[1] & 0x80 != 0,
            "client-encoded frame must have MASK bit set"
        );
    }

    /// Server-encoded frames never have the mask bit set.
    #[test]
    fn server_frames_are_unmasked(payload in arb_payload_any(), opcode in arb_data_opcode()) {
        init_test_logging();
        let frame = match opcode {
            Opcode::Text => Frame::text(Bytes::from(payload)),
            Opcode::Binary => Frame::binary(Bytes::from(payload)),
            _ => unreachable!(),
        };

        let mut encoder = FrameCodec::server();
        let mut buf = BytesMut::new();
        encoder.encode(frame, &mut buf).unwrap();

        // Second byte's high bit should be 0
        prop_assert!(
            buf[1] & 0x80 == 0,
            "server-encoded frame must not have MASK bit set"
        );
    }
}

// ============================================================================
// Multiple Frames in Sequence
// ============================================================================

proptest! {
    #![proptest_config(test_proptest_config(100))]

    /// Multiple frames encoded sequentially decode in order.
    #[test]
    fn sequential_frames_preserve_order(
        payloads in prop::collection::vec(arb_payload_small(), 2..=8)
    ) {
        init_test_logging();
        let mut encoder = FrameCodec::client();
        let mut decoder = FrameCodec::server();
        let mut buf = BytesMut::new();

        // Encode all frames into one buffer
        for payload in &payloads {
            let frame = Frame::binary(Bytes::from(payload.clone()));
            encoder.encode(frame, &mut buf).unwrap();
        }

        // Decode all frames and verify order
        for (i, expected) in payloads.iter().enumerate() {
            let parsed = decoder.decode(&mut buf).unwrap();
            prop_assert!(
                parsed.is_some(),
                "frame {i} should decode successfully"
            );
            let parsed = parsed.unwrap();
            prop_assert!(
                parsed.payload.as_ref() == expected.as_slice(),
                "frame {} payload mismatch", i
            );
        }

        // Buffer should be empty after decoding all frames
        prop_assert!(buf.is_empty(), "buffer should be empty after all frames decoded");
    }
}
